"""Authenticated host-side LAN discovery service for Shadow Map GRC."""

import hmac
import os

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from scanner.network_discovery import (
    NetworkDiscoveryError,
    discover_hosts,
    get_network_interfaces,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

TOKEN = os.environ.get("SHADOW_MAP_HOST_AGENT_TOKEN", "")
HOST = os.environ.get("SHADOW_MAP_HOST_AGENT_BIND", "127.0.0.1")


def _validated_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "SHADOW_MAP_HOST_AGENT_PORT must be an integer from 1 to 65535."
        ) from exc
    if not 1 <= port <= 65535:
        raise RuntimeError(
            "SHADOW_MAP_HOST_AGENT_PORT must be between 1 and 65535."
        )
    return port


PORT = _validated_port(os.environ.get("SHADOW_MAP_HOST_AGENT_PORT", "5001"))


@app.before_request
def authenticate():
    supplied = request.headers.get("Authorization", "")
    expected = f"Bearer {TOKEN}"

    if not TOKEN or not hmac.compare_digest(supplied, expected):
        return jsonify({"error": "Unauthorized"}), 401


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/interfaces")
def interfaces():
    try:
        return jsonify({"interfaces": get_network_interfaces()})
    except NetworkDiscoveryError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/scan")
def scan():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON request is required."}), 400

    interface = data.get("interface")
    subnet = data.get("subnet")

    if data.get("authorized") is not True:
        return jsonify({"error": "Explicit scan authorization is required."}), 403

    if not isinstance(interface, str) or not isinstance(subnet, str):
        return jsonify({"error": "A valid interface and subnet are required."}), 400

    try:
        result = discover_hosts(
            subnet,
            interface,
            authorized=True,
        )
        return jsonify(result)

    except NetworkDiscoveryError as exc:
        return jsonify({"error": str(exc)}), 400


def main():
    if not TOKEN:
        raise SystemExit(
            "SHADOW_MAP_HOST_AGENT_TOKEN must be configured before startup."
        )

    print(f"Shadow Map GRC host agent listening on {HOST}:{PORT}")

    server = make_server(HOST, PORT, app, threaded=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
