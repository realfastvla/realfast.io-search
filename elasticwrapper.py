from flask import Flask, render_template, request
import requests
import json
from elasticsearch import Elasticsearch

app = Flask(__name__)
es = Elasticsearch("http://go-nrao-nm.aoc.nrao.edu:9200")

def sanitize(s):
    s = s.replace("&", "&amp")
    s = s.replace(">", "&gt")
    s = s.replace("<", "&lt")
    return s

@app.route("/")
def index():
    #return the frontend
    return render_template("index.html")

@app.route("/scans")
def obs_index():
    #return the frontend
    return render_template("index_scans.html")

@app.route("/cands")
def obs_cands():
    #return the frontend
    return render_template("index_cands.html")

@app.route("/api", defaults={"query": ""}, methods=["GET"])
@app.route("/api/<path:query>", methods=["GET"])
def get_api(query):
    #return requests from elasticsearch at NRAO
    query = "/".join(request.full_path.split("/")[2:])
    resp = requests.get("http://go-nrao-nm.aoc.nrao.edu:9200/" + query)
    return resp.text
    #return json.dumps(resp.json())

@app.route("/api/add_tag/<id>", methods=["POST"])
def add_candidate_tag(id):
    tag = sanitize(request.form["tag"])
    resp = es.update("realfast", "cand", id, {"script": "if (!ctx._source.tags.contains('" + tag + "')) { ctx._source.tags.add('" + tag + "') }"})
    return json.dumps(resp)

@app.route("/api/remove_tag/<id>", methods=["POST"])
def remove_candidate_tag(id):
    tag = request.form["tag"].replace(";", "")
    resp = es.update("realfast", "cand", id, {"script": "if (ctx._source.tags.contains('" + tag + "')) { ctx._source.tags.remove(ctx._source.tags.indexOf('" + tag + "')) }"})
    return json.dumps(resp)
