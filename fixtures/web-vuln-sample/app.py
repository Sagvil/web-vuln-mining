import os
import sqlite3

import requests
from flask import Flask, request


app = Flask(__name__)


def find_user(user_id: str):
    connection = sqlite3.connect("sample.db")
    return connection.execute(f"SELECT * FROM users WHERE id = '{user_id}'").fetchall()


def fetch_preview(url: str):
    return requests.get(url, timeout=5).text


def download_path(filename: str):
    return os.path.join("uploads", filename)


@app.get("/users")
def users():
    """Intentionally unsafe local fixture route for source-analysis acceptance checks."""
    return {"users": find_user(request.args.get("id", "0"))}
