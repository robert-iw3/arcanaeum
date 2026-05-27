import pytest
import os
import json
import uuid
from pathlib import Path
from static_code_analyzer.scanner import StaticCodeAnalyzer
from static_code_analyzer.log import Logger
from static_code_analyzer.api import app
from flask.testing import FlaskClient
import jwt
from datetime import datetime, timedelta
import psycopg2
import asyncio

@pytest.fixture
def temp_dir(tmp_path):
    test_files = {
        "test.py": 'password = "secret123"\neval("print(1)")\nhttp.get("http://example.com")',
        "test.js": 'const secret = "abc123";\neval("alert(1)");\napp.use("/api")',
        "test.java": 'String secret = "xyz123";\nHttpSession.setAttribute("user", value);',
        "package.json": '{"dependencies": {"lodash": "4.17.20"}}'
    }
    for name, content in test_files.items():
        (tmp_path / name).write_text(content)
    return tmp_path

@pytest.fixture
def analyzer(temp_dir):
    db_config = {
        "host": "localhost",
        "port": "5432",
        "database": "analyzer",
        "user": "analyzer",
        "password": "securepassword"
    }
    config_file = temp_dir / "config.yaml"
    config_file.write_text("""
log_file: /app/logs/test.log
extensions:
  - .py
  - .js
  - .java
  - .json
custom_functions:
  - function: "eval()"
    description: "Test eval detection"
    category: "security"
    severity: "Critical"
    owasp_category: "A03:2021"
cve_patterns:
  - dependency: lodash
    version: '<4.17.21'
    cve: CVE-2021-23337
""")
    return StaticCodeAnalyzer(
        folder=str(temp_dir),
        language=None,
        output=str(temp_dir / "results.json"),
        output_format="json",
        config_file=str(config_file),
        api_url=None,
        db_config=db_config
    )

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["JWT_SECRET"] = "test_secret"
    app.config["DB_HOST"] = "localhost"
    app.config["DB_PORT"] = "5432"
    app.config["DB_NAME"] = "analyzer"
    app.config["DB_USER"] = "analyzer"
    app.config["DB_PASSWORD"] = "securepassword"
    return app.test_client()

@pytest.fixture
def token():
    return jwt.encode(
        {"sub": "test_user", "exp": datetime.utcnow() + timedelta(hours=1)},
        "test_secret",
        algorithm="HS256"
    )

@pytest.fixture
def db_connection():
    conn = psycopg2.connect(
        host="localhost",
        port="5432",
        database="analyzer",
        user="analyzer",
        password="securepassword"
    )
    with conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS scan_results (id SERIAL PRIMARY KEY, data JSONB NOT NULL, timestamp TIMESTAMP NOT NULL)")
        conn.commit()
    yield conn
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS scan_results")
        conn.commit()
    conn.close()

def test_init(analyzer):
    assert analyzer.folder.exists()
    assert len(analyzer.pattern_cache) > 10
    assert analyzer.output_format == "json"
    assert analyzer.logger is not None
    assert analyzer.config["batch_size"] == 1000
    assert analyzer.chunk_size == 1048576

def test_load_config(analyzer):
    config = analyzer._load_config(str(analyzer.folder / "config.yaml"))
    assert config["log_file"] == "/app/logs/test.log"
    assert "custom_functions" in config
    assert len(config["cve_patterns"]) >= 3

def test_scan_file(temp_dir, analyzer):
    results = asyncio.run(analyzer._scan_file(temp_dir / "test.py"))
    assert len(results) >= 3  # eval, password, http.get
    assert any(r["function"] == r"\beval\s*\(" for r in results)
    assert any(r["function"] == r"\b(password|secret|apiKey)\s*=\s*['\"][^'\"]+['\"]" for r in results)
    assert any(r["function"] == r"\bhttp\.get\s*\(\s*['\"][^'\"]+['\"]\s*\)" for r in results)

def test_cve_check(temp_dir, analyzer):
    content = (temp_dir / "package.json").read_text()
    matches = analyzer._check_cve(temp_dir / "package.json", content)
    assert len(matches) == 1
    assert matches[0]["cve_id"] == "CVE-2021-23337"
    assert matches[0]["dependency"] == "lodash"

def test_scan(temp_dir, analyzer):
    analyzer.scan()
    assert analyzer.summary["total_files"] == 4
    assert analyzer.summary["files_scanned"] > 0
    assert analyzer.summary["vulnerabilities"] >= 5
    assert (temp_dir / "results.json").exists()
    with open(temp_dir / "results.json") as f:
        data = json.load(f)
        assert len(data["results"]) >= 5
        assert "cve_matches" in data["summary"]
        assert len(data["summary"]["cve_matches"]) == 1
        assert data["summary"]["by_owasp"]["A10:2021"] >= 1

def test_get_results(client, temp_dir, token, db_connection):
    data = {
        "results": [{"file": "test.py", "line": 1, "function": "eval()", "description": "Test eval", "category": "security", "severity": "Critical", "owasp_category": "A03:2021", "language": "python", "timestamp": "2025-09-04T12:00:00Z", "scan_id": str(uuid.uuid4()), "confidence": "High"}],
        "summary": {"total_files": 1, "files_scanned": 1, "vulnerabilities": 1, "by_severity": {"Critical": 1}, "cve_matches": []}
    }
    with db_connection.cursor() as cur:
        cur.execute("INSERT INTO scan_results (data, timestamp) VALUES (%s, %s)", (json.dumps(data), datetime.utcnow().isoformat()))
        db_connection.commit()
    response = client.get("/results", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    result = response.json
    assert len(result["results"]) == 1
    assert result["summary"]["by_severity"] == {"Critical": 1}

def test_get_results_no_token(client, temp_dir, db_connection):
    response = client.get("/results")
    assert response.status_code == 200
    assert response.json == {"results": [], "summary": {"total_files": 0, "files_scanned": 0, "vulnerabilities": 0, "cve_matches": []}}

def test_post_results(client, token, db_connection):
    data = {
        "results": [{"file": "test.py", "line": 1, "function": "eval()", "description": "Test eval", "category": "security", "severity": "Critical", "owasp_category": "A03:2021", "language": "python", "timestamp": "2025-09-04T12:00:00Z", "scan_id": str(uuid.uuid4()), "confidence": "High"}],
        "summary": {"total_files": 1, "files_scanned": 1, "vulnerabilities": 1, "by_severity": {"Critical": 1}, "cve_matches": []}
    }
    response = client.post("/results", json=data, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json == {"status": "success"}
    assert "jwt_token" in response.headers["Set-Cookie"]
    with open("/app/results/results.json") as f:
        saved = json.load(f)
        assert saved["results"][0]["function"] == "eval()"
    with db_connection.cursor() as cur:
        cur.execute("SELECT data FROM scan_results ORDER BY timestamp DESC LIMIT 1")
        saved = cur.fetchone()[0]
        assert saved["results"][0]["function"] == "eval()"

def test_post_results_invalid_token(client):
    response = client.post("/results", json={}, headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401
    assert response.json == {"error": "Invalid JWT token"}

def test_post_results_invalid_schema(client, token):
    data = {"results": [], "summary": {}}
    response = client.post("/results", json=data, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 400
    assert "Validation error" in response.json["error"]

def test_health_check(client, db_connection):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "healthy"}