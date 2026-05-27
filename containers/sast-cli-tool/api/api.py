from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import psycopg2
from datetime import datetime, timedelta
import os
import json
import jsonschema
from jsonschema import validate
from static_code_analyzer.log import Logger
import logging.handlers

app = Flask(__name__)
CORS(app, resources={r"/results": {"origins": "https://localhost:443"}})
limiter = Limiter(
    app,
    key_func=lambda: jwt.decode(
        request.headers.get("Authorization", "").replace("Bearer ", ""),
        os.getenv("JWT_SECRET"),
        algorithms=["HS256"]
    ).get("sub", get_remote_address()),
    default_limits=["10 per second"]
)

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": os.getenv("DB_PORT", "5432"),
    "database": os.getenv("DB_NAME", "analyzer"),
    "user": os.getenv("DB_USER", "analyzer"),
    "password": os.getenv("DB_PASSWORD", "securepassword")
}

logger = Logger("/app/logs/api.log")
handler = logging.handlers.RotatingFileHandler(
    "/app/logs/api.log", maxBytes=10*1024*1024, backupCount=5
)
handler.setFormatter(logging.Formatter('{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "user": "%(user)s"}'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "function": {"type": "string"},
                    "description": {"type": "string"},
                    "category": {"type": "string"},
                    "severity": {"type": "string"},
                    "owasp_category": {"type": "string"},
                    "language": {"type": "string"},
                    "timestamp": {"type": "string"},
                    "scan_id": {"type": "string"},
                    "confidence": {"type": "string"}
                },
                "required": ["file", "line", "function", "description", "category", "severity", "owasp_category", "language", "timestamp", "scan_id", "confidence"]
            }
        },
        "summary": {
            "type": "object",
            "properties": {
                "total_files": {"type": "integer"},
                "files_scanned": {"type": "integer"},
                "vulnerabilities": {"type": "integer"},
                "scan_start": {"type": "string"},
                "scan_end": {"type": "string"},
                "by_owasp": {"type": "object"},
                "by_severity": {"type": "object"},
                "by_category": {"type": "object"},
                "by_language": {"type": "object"},
                "cve_matches": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "dependency": {"type": "string"},
                            "version": {"type": "string"},
                            "cve_id": {"type": "string"},
                            "file": {"type": "string"},
                            "severity": {"type": "string"},
                            "description": {"type": "string"},
                            "published_date": {"type": "string"},
                            "cvss_score": {"type": "number"}
                        },
                        "required": ["dependency", "version", "cve_id", "file", "severity", "description"]
                    }
                }
            },
            "required": ["total_files", "files_scanned", "vulnerabilities"]
        }
    },
    "required": ["results", "summary"]
}

def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        app.logger.error(f"Database connection failed: {str(e)}", extra={"user": "system"})
        raise

@app.route("/results", methods=["GET"])
def get_results():
    user = "anonymous"
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            user = payload.get("sub", "anonymous")
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT data FROM scan_results ORDER BY timestamp DESC LIMIT 1")
            row = cur.fetchone()
            data = row[0] if row else {"results": [], "summary": {"total_files": 0, "files_scanned": 0, "vulnerabilities": 0, "cve_matches": []}}
        conn.close()
        by_severity = data.get("summary", {}).get("by_severity", {})
        data["summary"]["by_severity"] = dict(sorted(
            by_severity.items(),
            key=lambda x: ["Critical", "High", "Medium", "Low"].index(x[0]) if x[0] in ["Critical", "High", "Medium", "Low"] else len(by_severity)
        ))
        app.logger.info(f"GET /results: Retrieved {len(data['results'])} results", extra={"user": user})
        return jsonify(data)
    except jwt.InvalidTokenError:
        app.logger.error("GET /results: Invalid JWT", extra={"user": user})
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        app.logger.error(f"GET /results failed: {str(e)}", extra={"user": user})
        return jsonify({"error": str(e)}), 500

@app.route("/results", methods=["POST"])
@limiter.limit("10 per second")
def post_results():
    user = "anonymous"
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        app.logger.error("POST /results: Invalid authorization header", extra={"user": user})
        return jsonify({"error": "Invalid authorization header"}), 401
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = payload.get("sub", "anonymous")
    except jwt.InvalidTokenError:
        app.logger.error("POST /results: Invalid JWT token", extra={"user": user})
        return jsonify({"error": "Invalid JWT token"}), 401

    try:
        data = request.get_json()
        validate(instance=data, schema=SCHEMA)
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scan_results (data, timestamp) VALUES (%s, %s)",
                (json.dumps(data), datetime.utcnow().isoformat())
            )
            conn.commit()
        conn.close()
        with open("/app/results/results.json", "w") as f:
            json.dump(data, f, indent=2)
        app.logger.info(
            f"POST /results: Saved {len(data['results'])} results, scan_id: {data['results'][0]['scan_id'] if data['results'] else 'empty'}",
            extra={"user": user}
        )
        response = make_response(jsonify({"status": "success"}))
        response.set_cookie("jwt_token", token, httponly=True, secure=True, samesite="Strict", max_age=3600)
        return response
    except jsonschema.ValidationError as e:
        app.logger.error(f"POST /results: Validation error: {str(e)}", extra={"user": user})
        return jsonify({"error": f"Validation error: {str(e)}"}), 400
    except Exception as e:
        app.logger.error(f"POST /results failed: {str(e)}", extra={"user": user})
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health():
    app.logger.info("Health check: OK", extra={"user": "system"})
    try:
        conn = get_db_connection()
        conn.close()
        return jsonify({"status": "healthy"})
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}", extra={"user": "system"})
        return jsonify({"status": "unhealthy", "error": str(e)}), 500