"""
TEST FIXTURE ONLY — BENCHMARK TARGET
------------------------------------
This file is NOT part of PuedoBot! PuedoBot is 100% a pure CLI security tool.
This file is a mock dummy codebase used purely as a target to verify that
PuedoBot's engines can detect SQL injections and ignore safe parameterized queries.
"""

from flask import Flask, request, render_template_string
import sqlite3
import requests

app = Flask(__name__)


class Document:
    """Mock model to satisfy linter for IDOR benchmark test."""
    class query:
        @staticmethod
        def get(doc_id):
            return Document()
    body = "Mock document body content"


@app.route("/user")
def get_user():
    name = request.args["name"]
    cur = sqlite3.connect("db.sqlite").cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # EXPECT: sql_injection
    return str(cur.fetchall())


@app.route("/user-safe")
def get_user_safe():
    name = request.args["name"]
    cur = sqlite3.connect("db.sqlite").cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # SAFE
    return str(cur.fetchall())


@app.route("/greet")
def greet():
    return render_template_string("Hello " + request.args["n"])  # EXPECT: template_injection


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text  # GAP: ssrf


@app.route("/doc/<doc_id>")
def get_doc(doc_id):
    return Document.query.get(doc_id).body  # GAP: idor
