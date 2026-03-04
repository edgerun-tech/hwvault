#!/usr/bin/env python3
"""
Minimal demo 2FA backend for hwvault resolver.

Endpoints:
- POST /v1/approvals           -> create request
- GET  /v1/approvals/<id>      -> poll request status
- POST /v1/approvals/<id>/approve
- POST /v1/approvals/<id>/deny

Auth:
- Authorization: Bearer <token>
- token from env HWVAULT_SECOND_FACTOR_HTTP_BEARER
"""
from flask import Flask, request, jsonify, abort
import os

app = Flask(__name__)
STORE = {}
TOKEN = os.environ.get("HWVAULT_SECOND_FACTOR_HTTP_BEARER", "change-me")


def check_auth():
    h = request.headers.get("Authorization", "")
    if h != f"Bearer {TOKEN}":
        abort(401)


@app.post("/v1/approvals")
def create_approval():
    check_auth()
    data = request.get_json(force=True, silent=False)
    rid = data.get("requestId")
    if not rid:
        return jsonify({"error": "missing requestId"}), 400
    STORE[rid] = {
        "status": "pending",
        "action": data.get("action"),
        "secretId": data.get("secretId"),
    }
    return jsonify({"ok": True, "requestId": rid})


@app.get("/v1/approvals/<rid>")
def get_approval(rid):
    check_auth()
    item = STORE.get(rid)
    if not item:
        return jsonify({"status": "denied", "requestId": rid}), 404
    return jsonify({
        "status": item["status"],
        "requestId": rid,
        "action": item.get("action"),
        "secretId": item.get("secretId"),
    })


@app.post("/v1/approvals/<rid>/approve")
def approve(rid):
    check_auth()
    if rid not in STORE:
        return jsonify({"error": "not found"}), 404
    STORE[rid]["status"] = "approved"
    return jsonify({"ok": True})


@app.post("/v1/approvals/<rid>/deny")
def deny(rid):
    check_auth()
    if rid not in STORE:
        return jsonify({"error": "not found"}), 404
    STORE[rid]["status"] = "denied"
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8787)
