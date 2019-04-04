from flask import Flask, render_template, request, session, url_for, redirect, flash, make_response, current_app
from flask_cors import CORS
import requests
import urllib
import json
from elasticsearch import Elasticsearch, TransportError
import pdb
from datetime import datetime, timedelta
from functools import update_wrapper
import markdown
from threading import Lock
import os
from math import degrees

app = Flask(__name__)
CORS(app)
app.secret_key = b'r8\x9f\xbda\xc8q]]\x9e\xbc\x82y\x08h\x95\x8b\xc9\xcb\xa8\xd8\x90\x93\x18'
es = Elasticsearch("http://realfast.nrao.edu:9200", timeout=20, retry_on_timeout=True)
log_lock = Lock()
index_prefixes = ["new", "final", "test", "chime", "aws"]
nature_tags = ["rfi", "instrumental", "unsure", "astrophysical", "mock"]
action_tags = ["delete", "archive", "notify"]
allowed_tags = nature_tags + action_tags

def sanitize(s):
    s = s.replace("&", "&amp")
    s = s.replace(">", "&gt")
    s = s.replace("<", "&lt")
    return s

def log(action, target):
    try:
        log_lock.acquire()
        with open("logs/active.log", "a") as log_file:
            time = str(datetime.now())
            log_file.write("[%s] %s %s on %s\n\n" % (time, session["userid"], action, target))
    finally:
        log_lock.release()

@app.route("/clear-prefix")
def clear_prefix():
    session["prefix"] = ""
    return "done"

@app.route("/set-prefix/<pre>")
def set_prefix(pre):
    session["prefix"] = str(pre)
    return "set prefix to {0}".format(pre)

@app.route("/get-prefix")
def get_prefix():
    return session["prefix"]

@app.route("/get-curr-log")
def get_curr_log():
    if session["logged_in"]:
        try:
            log_lock.acquire()
            with open("logs/active.log", "r") as log_file:
                contents = log_file.read()
                return '<a href="/checkpoint-log"><button>Checkpoint</button></a><br><br>'+ markdown.markdown(contents)
        finally:
            log_lock.release()
    else:
        return "Not allowed!"

@app.route("/checkpoint-log")
def checkpoint_log():
    if session["logged_in"]:
        try:
            log_lock.acquire()
            with open("logs/active.log", "r") as log_file:
                contents = log_file.read()
                # email to casey
                os.rename("logs/active.log", "logs/checkpoint%s.log" % str(datetime.now()).replace(" ", "_"))
                open("logs/active.log", "w+").close()
        finally:
            log_lock.release()
            flash("Successfully saved log!", "success")
            return redirect(url_for("index"), code=302)
    else:
        flash("Not allowed!", "error")
        return redirect(url_for("index"), code=302)

@app.route("/")
def index():
    # return the frontend
    return render_template("index.html", index_prefixes=index_prefixes, action_tags=action_tags, nature_tags=nature_tags, allowed_tags=allowed_tags, curr_tab=0)

@app.route("/filter")
def filter_by_tag():
    # set a session cookie to preprocess all queries
    return

@app.route("/login")
def login():
    return redirect("https://github.com/login/oauth/authorize?client_id=8173db015b7e84e42753", code=302)

@app.route("/callback")
def callback():
        code = request.args.get("code")
        resp = requests.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, data={"client_id": "8173db015b7e84e42753", "client_secret": "b725cf9fb677aa0b743ea68b524e6f10ff93e7b8", "code": code})
        data = resp.json()
        access_token = data["access_token"]
        resp = requests.get("https://api.github.com/user", headers={"Authorization": "token " + access_token, "Accept": "application/json"})
        userid = resp.json()["login"]
        allowed_users = open("allowed_users", "r").read().split()
        if userid in allowed_users:
            session["logged_in"] = True
            session["userid"] = userid
            flash("Successfully logged in!", "success")
        else:
            flash("Invalid credentials", "error")
        return redirect(url_for("index"), code=302)

@app.route("/logout")
def logout():
    del session["logged_in"]
    del session["userid"]
    return redirect(url_for("index"), code=302)

@app.route("/api", defaults={"query": ""}, methods=["GET"])
@app.route("/api/<path:query>", methods=["GET"])
def get_api(query):
    #return requests from elasticsearch at NRAO
    source = request.args.get("source")
    if source:
        session["last_request"] = json.loads(urllib.parse.unquote(source))["query"]
        try:
            # try to replace '\\:' from URL encoding with ':'
            session["last_request"]["query_string"]["query"] = session["last_request"]["query_string"]["query"].replace("\\:", ":")
            session["last_request"]["query_string"]["query"] = session["last_request"]["query_string"]["query"].replace("\\(", "(")
            session["last_request"]["query_string"]["query"] = session["last_request"]["query_string"]["query"].replace("\\)", ")")
            session["request_string"] = session["last_request"]["query_string"]["query"]
        except KeyError:
            print("KeyError for session last request: {0}".format(session["last_request"]))

    if session.get("logged_in"):
        if "prefix" in session.keys():
            prefix = session["prefix"]
        else:
            prefix = "new"
        query = request.full_path.split("/")[2:]
        query[0] = prefix + query[0]
        query[1] = prefix + query[1]
        query = "/".join(query)
        print(query)
        # get rid of backslashes in URL (but not before "), it seems facetview doesn't account for this
        query = query.replace("%5C%5C", "")
        resp = requests.get("http://realfast.nrao.edu:9200/" + query)
        resp = make_response(resp.text)
        resp.set_cookie("last_request", str(session["last_request"]))
        return resp
    else:
        query_obj = json.loads(urllib.parse.unquote(request.args.get("source")))
        old_query = query_obj["query"]
        if "query_string" in old_query.keys():
            old_query2 = old_query["query_string"]
            print("old_query2", old_query2)
        else:
            print("old_query", old_query)
        new_query = {"bool": {"must":  {"match": {"tags": "public"}}}}
#        new_query = {"bool": {"must": [{"match": old_query}, {"match": {"tags": "public"}}]}}  # "must" can take a list, so this is almost right
        query_obj["query"] = new_query
        query_string = urllib.parse.quote(json.dumps(query_obj))
        path = '/'.join([pth for pth in request.path.split("/")[2:]])
        path = path.replace('cands/cand', 'finalcands/finalcand')  # this returns 1 cand. why?**
        fullpath = "http://realfast.nrao.edu:9200/" + path + "?source=" + query_string
        resp = requests.get(fullpath)
        print("*"*100)
        print("fullpath:", fullpath)
#        print(query_obj)
        print("resp.text", resp.text)
        print("*"*100)
        return resp.text


@app.route("/api/add_tag/<id>", methods=["GET"])
def add_candidate_tag(id):
    tag = sanitize(request.args.get("tag"))
    if tag not in allowed_tags:
        return
    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"

    # experimental guard
#    if prefix != "test":
#        raise ValueError("can't use this feature outside test index on experimental branch")
    # end guard

    doc = es.get(index=prefix+"cands", doc_type=prefix+"cand", id=id, _source=[session["userid"]+"_tags"])
    if session["userid"]+"_tags" in doc["_source"]:
        curr_tags = doc["_source"][session["userid"]+"_tags"]
        tag_list = curr_tags.split(",")
        if tag in tag_list:
            return
        else:
            tag_list.append(tag)
            new_tags = ",".join(tag_list)
#            if "tagcount" in doc["_source"]:
#                new_tagcount = doc["_source"]["tagcount"] + 1
#            else:
#                new_tagcount = 1
    else:
        new_tags = tag
#        if "tagcount" in doc["_source"]:
#            new_tagcount = doc["_source"]["tagcount"] + 1
#        else:
#            new_tagcount = 1
    resp = es.update(prefix+"cands", prefix+"cand", id, {"doc": {session["userid"]+"_tags": new_tags}})
    resp = es.update(prefix+"cands", prefix+"cand", id, {"script": 'ctx._source.tagcount += 1'})
    log("added tag %s" % tag, "candidate %s" % id)
    return json.dumps(resp)

@app.route("/api/remove_tag/<id>", methods=["GET"])
def remove_candidate_tag(id):
    tag = sanitize(request.args.get("tag"))
    if tag not in allowed_tags:
        return
    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"

    # experimental guard
#    if prefix != "test":
#        raise ValueError("can't use this feature outside test index on experimental branch")
    # end guard

    doc = es.get(index=prefix+"cands", doc_type=prefix+"cand", id=id, _source=[session["userid"]+"_tags"])
    if session["userid"]+"_tags" in doc["_source"]:
        curr_tags = doc["_source"][session["userid"]+"_tags"]
        tag_list = curr_tags.split(",")
        if tag not in tag_list:
            return
        else:
            tag_list.remove(tag)
            new_tags = ",".join(tag_list)
    else:
        return
    if new_tags != "":
        resp = es.update(prefix+"cands", prefix+"cand", id, {"doc": {session["userid"]+"_tags": new_tags}})
    else:
        resp = es.update(prefix+"cands", prefix+"cand", id, {"script": 'ctx._source.remove("' + session["userid"]+"_tags" + '"); ctx._source.tagcount -= 1'})

    log("removed tag %s" % tag, "candidate %s" % id)
    return json.dumps(resp)


@app.route("/api/scan-info/<id>")
def get_scan_info(id):
    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"

    try:
        resp = es.get(index=prefix+"scans", doc_type=prefix+"scan", id=id, request_timeout=1)
        if resp['found']:
            doc = resp["_source"]
            scanId = doc["scanId"]
            scanIdLink = "http://search.realfast.io/?source=%7B%22query%22%3A%7B%22query_string%22%3A%7B%22query%22%3A%22scanId%5C%5C%3A%5C%22idgoeshere%5C%22%22%2C%22default_operator%22%3A%22OR%22%7D%7D%2C%22sort%22%3A%5B%7B%22snr1%22%3A%7B%22order%22%3A%22desc%22%7D%7D%5D%2C%22from%22%3A0%2C%22size%22%3A10%7D".replace("idgoeshere", scanId)
            scanNo = doc["scanNo"]
            subscanNo = doc["subscanNo"]
            startTime = doc["startTime"]
            stopTime = doc["stopTime"]
            ra = doc["ra"]
            dec = doc["dec"]
            source = doc["source"]
            scan_intent = doc["scan_intent"]
            datasource = doc["datasource"]
            prefsname = doc["prefsname"]
            searchtype = doc["searchtype"] if "searchtype" in doc else None
            fftmode = doc["fftmode"] if "fftmode" in doc else None
            return render_template("scan_info.html", scanIdLink=scanIdLink, scanId=scanId, scanNo=scanNo, subscanNo=subscanNo, startTime=startTime, stopTime=stopTime, ra=ra, dec=dec, source=source, scan_intent=scan_intent, datasource=datasource, prefsname=prefsname, searchtype=searchtype, fftmode=fftmode)
        else:
            return "No scan found for id {0}".format(id)
    except TransportError:
        return "No scan found for id {0}".format(id)


@app.route("/api/query-cand/<id>")
def get_coord_info(id):
    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"

    try:
        resp = es.get(index=prefix+"cands", doc_type=prefix+"cand", id=id, request_timeout=1)
        if resp['found']:
            doc = resp["_source"]
            ra = doc["ra"]
            dec = doc["dec"]
            from rf_meta_query import frb_cand, radio
            frbc = frb_cand.build_frb_cand(ra, dec, 11111)
            first_cat, first_summary = radio.query_first(frbc)
            if "sdmname" in doc.keys():
                sdmname = doc["sdmname"]
                return ("Candidate at RA, Dec = ({0}, {1}). SDM named {2}. {3}"
                        .format(ra, dec, sdmname, first_summary[0]))
            else:
                return "Candidate at RA, Dec = ({0}, {1}). {2}".format(ra, dec, first_summary[0])
        else:
            return "No candId {1} found".format(scanId, id)            
    except TransportError:
        return "No preferences found for id {0}".format(id)


@app.route("/api/preference-info/<id>")
def get_preference_info(id):
    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"

    try:
        resp = es.get(index=prefix+"preferences", doc_type=prefix+"preference", id=id, request_timeout=1)
        if resp['found']:
            doc = resp["_source"]
            chans = doc["chans"]
            clustercands = doc["clustercands"]
            dmarr = doc["dmarr"]
            dtarr = doc["dtarr"]
            fftmode = doc["fftmode"]
            flaglist = doc["flaglist"]
            if "gainfile" in doc:
                gainfile = doc["gainfile"]
            else:
                gainfile = None
            maxdm = doc["maxdm"]
            maximmem = doc["maximmem"]
            memory_limit = doc["memory_limit"]
            npix_max = doc["npix_max"]
            npixx = doc["npixx"]
            npixy = doc["npixy"]
            rfpipe_version = doc["rfpipe_version"]
            savecandcollection = doc["savecandcollection"]
            savenoise = doc["savenoise"]
            searchtype = doc["searchtype"]
            selectpol = doc["selectpol"]
            sigma_image1 = doc["sigma_image1"]
            sigma_kalman = doc["sigma_kalman"]
            simulated_transient = doc["simulated_transient"]
            timesub = doc["timesub"]
            uvoversample = doc["uvoversample"]
            uvres = doc["uvres"]
            workdir = doc["workdir"]
            
            return render_template("preference_info.html", prefsname=id, chans=chans, clustercands=clustercands, dmarr=dmarr, dtarr=dtarr, fftmode=fftmode, gainfile=gainfile, maxdm=maxdm, flaglist=flaglist, maximmem=maximmem, memory_limit=memory_limit, npix_max=npix_max, npixx=npixx, npixy=npixy, rfpipe_version=rfpipe_version, savecandcollection=savecandcollection, savenoise=savenoise, searchtype=searchtype, selectpol=selectpol, sigma_image1=sigma_image1, sigma_kalman=sigma_kalman, timesub=timesub, uvoversample=uvoversample, uvres=uvres, workdir=workdir)
        else:
            return "No scan found for id {0}".format(id)
    except TransportError:
        return "No preferences found for id {0}".format(id)

@app.route("/api/mock-info/<id>")
def get_mock_info(id):
    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"

    try:
        resp = es.get(index=prefix+"mocks", doc_type=prefix+"mock", id=id, request_timeout=1)
        if resp['found']:
            print("record = es.get(index={0}mocks, doc_type={0}mock, id={1})".format(prefix, id))
            doc = resp["_source"]
            scanId = doc["scanId"]
            segment = doc["segment"]
            integration = doc["integration"]
            dm = doc["dm"]
            dt = doc["dt"]
            amp = doc["amp"]
            l = doc["l"]
            m = doc["m"]
        
            return render_template("mock_info.html", scanId=scanId, segment=segment, integration=integration, dm=dm, dt=dt, amp=amp, l=l, m=m)
        else:
            return "No scan found for id {0}".format(id)
    except TransportError:
        return "No mocks found for id {0}".format(id)

@app.route("/api/get-cands-plot/<id>")
def get_cands_plot(id):

    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"

    resp = requests.get('http://realfast.nrao.edu/plots/{0}/cands_{1}.html'.format(prefix, id))
    if resp.status_code == 200:
        return resp.text
    else:
        return "No scan found for id {0}".format(id)

@app.route("/api/group-tag")
def group_tag():
    last_request = session.get("last_request")
    new_tags = request.args.get("tags")
    q = {
        "query": last_request,
        "script": {
            "inline": "if (ctx._source." + session["userid"] + "_tags == null) { ctx._source.tagcount += 1; } ctx._source." + session["userid"] + "_tags='" + new_tags + "'",
#            "inline": "ctx._source." + session["userid"] + "_tags='" + new_tags + "'",
            "lang": "painless"
        }
    }
    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"

    # experimental guard
#    if prefix != "test":
#        raise ValueError("can't use this feature outside test index on experimental branch")
    # end guard

    resp = es.update_by_query(body=q, doc_type=prefix+"cand", index=prefix+"cands")
    response_info = {"total": resp["total"], "updated": resp["updated"], "type": "success"}
    if resp["failures"] != []:
        response_info["type"] = "failure"
    log("group tagged %s" % new_tags, "query %s" % last_request)
    return json.dumps(response_info)

# not working?
@app.route("/api/group-tag-count")
def group_tag_count():
    if "prefix" in session.keys():
        prefix = session["prefix"]
    else:
        prefix = "new"
    last_request = session.get("last_request")
    q = {"query": last_request}
    resp = es.search(body=q, doc_type=prefix+"cand", index=prefix+"cands")
    response_info = {"total": resp["hits"]["total"]}
    return json.dumps(response_info)
