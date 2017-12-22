from flask import Flask, render_template, request, session, url_for, redirect, flash, make_response, current_app
from flask_cors import CORS
import requests
import urllib
import json
from elasticsearch import Elasticsearch
import pdb
from datetime import timedelta
from functools import update_wrapper


app = Flask(__name__)
CORS(app)
app.secret_key = b'r8\x9f\xbda\xc8q]]\x9e\xbc\x82y\x08h\x95\x8b\xc9\xcb\xa8\xd8\x90\x93\x18'
es = Elasticsearch("http://go-nrao-nm.aoc.nrao.edu:9200")

def sanitize(s):
    s = s.replace("&", "&amp")
    s = s.replace(">", "&gt")
    s = s.replace("<", "&lt")
    return s

@app.route("/")
def index():
    # return the frontend
    return render_template("index.html", curr_tab=0)

@app.route("/filter")
def filter_by_tag():
    # set a session cookie to preprocess all queries
    return

@app.route("/scans")
def scans_index():
    if request.args.get("id", ""):
        id = request.args.get("id", "")
    else:
        id = ""
    return render_template("index.html", curr_tab=1, id=id)

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
            flash("Successfully logged in!", "success")
        else:
            flash("Invalid credentials", "error")
        return redirect(url_for("index"), code=302)

@app.route("/logout")
def logout():
    del session["logged_in"]
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
            print("KeyError!")
        print("*"*100 + str(session["last_request"]))

    if session.get("logged_in"):
        query = "/".join(request.full_path.split("/")[2:])
        # get rid of backslashes in URL (but not before "), it seems facetview doesn't account for this
        query = query.replace("%5C%5C", "")
        resp = requests.get("http://go-nrao-nm.aoc.nrao.edu:9200/" + query)
        print(resp)
        resp = make_response(resp.text)
        resp.set_cookie("last_request", str(session["last_request"]))
        return resp
    else:
        query_obj = json.loads(urllib.parse.unquote(request.args.get("source")))
        old_query = query_obj["query"]
        new_query = {"bool": {"must": [{"match": {"tags": "public"}}]}}
        query_obj["query"] = new_query
        query_string = urllib.parse.quote(json.dumps(query_obj))
        resp = requests.get("http://go-nrao-nm.aoc.nrao.edu:9200/" + '/'.join(request.path.split("/")[2:]) + "?source=" + query_string)
        print("*"*100)
        print("http://go-nrao-nm.aoc.nrao.edu:9200/" + '/'.join(request.path.split("/")[2:]) + "?source=" + query_string)
        print(query_obj)
        print(resp.text)
        print("*"*100)
        return resp.text

@app.route("/api/add_tag/<id>", methods=["GET"])
def add_candidate_tag(id):
    allowed_tags = ["new", "rfi", "bad", "noise", "needs flagging", "needs review", "interesting", "pulsar", "frb", "mock", "public"]
    tag = sanitize(request.args.get("tag"))
    if tag not in allowed_tags:
        return
    doc = es.get(index="cands", doc_type="cand", id=id, _source=["tags"])
    old_tags = doc["_source"]["tags"]
    tags = old_tags.split(",")
    tags[allowed_tags.index(tag)] = tag
    new_tags = ",".join(tags)
    resp = es.update("cands", "cand", id, {"doc": {"tags": new_tags}})
    return json.dumps(resp)

@app.route("/api/remove_tag/<id>", methods=["GET"])
def remove_candidate_tag(id):
    allowed_tags = ["new", "rfi", "bad", "noise", "needs flagging", "needs review", "interesting", "pulsar", "frb", "mock", "public"]
    tag = sanitize(request.args.get("tag"))
    if tag not in allowed_tags:
        return
    doc = es.get(index="cands", doc_type="cand", id=id, _source=["tags"])
    old_tags = doc["_source"]["tags"]
    tags = old_tags.split(",")
    tags[allowed_tags.index(tag)] = "_"
    new_tags = ",".join(tags)
    resp = es.update("cands", "cand", id, {"doc": {"tags": new_tags}})
    return json.dumps(resp)

@app.route("/api/scan-info/<id>")
def get_scan_info(id):
    record = es.get(index="scans", doc_type="scan", id=id)
    doc = record["_source"]
    scanId = doc["scanId"]
    scanIdLink = "http://search.realfast.io/?source=%7B%22query%22%3A%7B%22query_string%22%3A%7B%22query%22%3A%22scanId%5C%5C%3A%5C%22idgoeshere%5C%22%22%2C%22default_operator%22%3A%22OR%22%7D%7D%2C%22sort%22%3A%5B%7B%22snr1%22%3A%7B%22order%22%3A%22desc%22%7D%7D%5D%2C%22from%22%3A0%2C%22size%22%3A10%7D".replace("idgoeshere", scanId)
    scanNo = doc["scanNo"]
    subscanNo = doc["subscanNo"]
    startTime = doc["startTime"]
    stopTime = doc["stopTime"]
    ra_deg = doc["ra_deg"]
    dec_deg = doc["dec_deg"]
    source = doc["source"]
    scan_intent = doc["scan_intent"]
    datasource = doc["datasource"]
    prefsname = doc["prefsname"]
    return render_template("scan_info.html", scanIdLink=scanIdLink, scanId=scanId, scanNo=scanNo, subscanNo=subscanNo, startTime=startTime, stopTime=stopTime, ra_deg=ra_deg, dec_deg=dec_deg, source=source, scan_intent=scan_intent, datasource=datasource, prefsname=prefsname)

@app.route("/api/preference-info/<id>")
def get_preference_info(id):
    record = es.get(index="preferences", doc_type="preference", id=id)
    doc = record["_source"]
    dmarr = doc["dmarr"]
    dtarr = doc["dtarr"]
    fftmode = doc["fftmode"]
    flaglist = doc["flaglist"]
    maxdm = doc["maxdm"]
    maximmem = doc["maximmem"]
    memory_limit = doc["memory_limit"]
    npix_max = doc["npix_max"]
    npixx = doc["npixx"]
    npixy = doc["npixy"]
    rfpipe_version = doc["rfpipe_version"]
    savecands = doc["savecands"]
    savenoise = doc["savenoise"]
    searchtype = doc["searchtype"]
    selectpol = doc["selectpol"]
    sigma_image1 = doc["sigma_image1"]
    sigma_image2 = doc["sigma_image2"]
    sigma_plot = doc["sigma_plot"]
    simulated_transient = doc["simulated_transient"]
    timesub = doc["timesub"]
    uvoversample = doc["uvoversample"]
    uvres = doc["uvres"]
    workdir = doc["workdir"]

    return render_template("preference_info.html", prefsname=id, dmarr=dmarr, dtarr=dtarr, fftmode=fftmode, maxdm=maxdm, flaglist=flaglist, maximmem=maximmem, memory_limit=memory_limit, npix_max=npix_max, npixx=npixx, npixy=npixy, rfpipe_version=rfpipe_version, savecands=savecands, savenoise=savenoise, searchtype=searchtype, selectpol=selectpol, sigma_image1=sigma_image1, sigma_image2=sigma_image2, sigma_plot=sigma_plot, simulated_transient=simulated_transient, timesub=timesub, uvoversample=uvoversample, uvres=uvres, workdir=workdir)

@app.route("/api/mock-info/<id>")
def get_mock_info(id):
    try:
        record = es.get(index="mocks", doc_type="mock", id=id)
        doc = record["_source"]
        scanId = doc["scanId"]
        segment = doc["segment"]
        integration = doc["integration"]
        dm = doc["dm"]
        dt = doc["dt"]
        amp = doc["amp"]
        l = doc["l"]
        m = doc["m"]
        
        return render_template("mock_info.html", scanId=scanId, segment=segment, integration=integration, dm=dm, dt=dt, amp=amp, l=l, m=m)
    except:
        return "No mocks found for id {0}".format(id)

@app.route("/api/get-cands-plot/<id>")
def get_cands_plot(id):
    resp = requests.get('http://www.aoc.nrao.edu/~claw/realfast/plots/cands_{0}.html'.format(id))
    if resp.status_code == 200:
        return resp.text
    else:
        return "No file found for id {0}".format(id)

@app.route("/api/group-tag")
def group_tag():
    last_request = session.get("last_request")
    new_tags = request.args.get("tags")
    q = {
        "query": last_request,
        "script": {
            "inline": "ctx._source.tags='" + new_tags + "'",
            "lang": "painless"
        }
    }
    resp = es.update_by_query(body=q, doc_type="cand", index="cands")
    response_info = {"total": resp["total"], "updated": resp["updated"], "type": "success"}
    if resp["failures"] != []:
        response_info["type"] = "failure"
    return json.dumps(response_info)

# not working?
@app.route("/api/group-tag-count")
def group_tag_count():
    last_request = session.get("last_request")
    q = {"query": last_request}
    resp = es.search(body=q, doc_type="cand", index="cands")
    response_info = {"total": resp["total"]}
    return json.dumps(response_info)
