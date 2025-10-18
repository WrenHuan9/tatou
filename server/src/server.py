import datetime as dt
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import secrets
import os
import pickle as _std_pickle
import html
from functools import wraps
from pathlib import Path
from typing import cast

from flask import Flask, g, jsonify, request, send_file
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import NotFound, MethodNotAllowed, HTTPException

try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle

import watermarking_utils as WMUtils
from watermarking_method import is_pdf_bytes

# from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method

rmap_service = None
identity_manager = None


def create_app():
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    # RMAP + Watermark unified configuration
    app.config["SERVER_PRIV_KEY_PATH"] = os.environ.get("SERVER_PRIV_KEY_PATH", "./keys/server_priv.asc")
    app.config["SERVER_PUB_KEY_PATH"] = os.environ.get("SERVER_PUB_KEY_PATH", "./keys/server_pub.asc")
    app.config["CLIENT_KEYS_DIR"] = os.environ.get("CLIENT_KEYS_DIR", "./keys/client_keys")
    app.config["PRIVATE_KEY_PASSPHRASE"] = os.environ.get("PRIVATE_KEY_PASSPHRASE")
    app.config["WATERMARK_METHOD"] = os.environ.get("WATERMARK_METHOD", "multi-location-robust-advanced")
    app.config["WATERMARK_KEY"] = os.environ.get("WATERMARK_KEY", "default-watermark-key-change-me")
    app.config["RMAP_SYSTEM_USER_ID"] = int(os.environ.get("RMAP_SYSTEM_USER_ID", "1"))
    app.config["RMAP_ADMIN_KEY"] = os.environ.get("RMAP_ADMIN_KEY", "change-this-admin-key")

    # Logging configuration
    app.config["LOG_DIR"] = Path(os.environ.get("LOG_DIR", "./logs")).resolve()
    app.config["LOG_LEVEL"] = os.environ.get("LOG_LEVEL", "INFO").upper()

    # Ensure log directory exists and is writable
    log_dir = app.config["LOG_DIR"]
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        # Test if we can write to the directory
        test_file = log_dir / ".test_write"
        test_file.touch()
        test_file.unlink()
        app.logger.info(f"Log directory {log_dir} is writable")
    except Exception as e:
        app.logger.warning(f"Cannot write to log directory {log_dir}: {e}")
        # Fallback to /tmp if log directory is not writable
        log_dir = Path("/tmp/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        app.config["LOG_DIR"] = log_dir
        app.logger.info(f"Using fallback log directory: {log_dir}")

    try:
        app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # Configure logging handlers
    log_file = app.config["LOG_DIR"] / "app.log"
    
    # Check if file handler already exists
    has_file_handler = any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers)
    has_stream_handler = any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler) for h in app.logger.handlers)
    
    # Add file handler if not present
    if not has_file_handler:
        try:
            file_handler = RotatingFileHandler(str(log_file), maxBytes=5 * 1024 * 1024, backupCount=20)
            formatter = logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            )
            file_handler.setFormatter(formatter)
            app.logger.addHandler(file_handler)
            app.logger.info(f"File logging enabled: {log_file}")
        except Exception as e:
            app.logger.warning(f"Failed to create file handler: {e}")
    
    # Add stream handler if not present
    if not has_stream_handler:
        stream_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        stream_handler.setFormatter(formatter)
        app.logger.addHandler(stream_handler)
        app.logger.info("Console logging enabled")
    
    app.logger.setLevel(getattr(logging, app.config["LOG_LEVEL"], logging.INFO))
    
    from security_monitor import SecurityMonitor
    global security_monitor
    security_monitor = SecurityMonitor(app.logger)

    @app.before_request
    def _log_request():
        # Store request info in g for later use
        g.request_start_time = dt.datetime.utcnow()
        g.client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
        docker_host_ip = '172.21.0.1'
        if g.client_ip == '172.21.0.1' or g.client_ip == docker_host_ip:
            pass
        elif security_monitor.check_rate_limiting(g.client_ip):
            app.logger.error(f"SECURITY_BLOCK: Rate limit exceeded for IP {g.client_ip}")
            return jsonify({"error": "Rate limit exceeded"}), 429

        if security_monitor.is_suspicious_ip(g.client_ip):
            app.logger.error(f"SECURITY_BLOCK: Suspicious IP {g.client_ip}")
            return jsonify({"error": "Access denied"}), 403

        if security_monitor.check_path_traversal(g.client_ip, request.path):
            app.logger.error(f"SECURITY_BLOCK: Path traversal attempt from IP {g.client_ip}")
            return jsonify({"error": "Invalid path"}), 400

        # Only log requests for API endpoints, skip static files
        if request.path.startswith('/api/'):
            try:
                user = getattr(g, "user", None)
            except Exception:
                user = None
            user_ctx = {
                "id": (user or {}).get("id") if isinstance(user, dict) else None,
                "login": (user or {}).get("login") if isinstance(user, dict) else None,
            }

            # Get request parameters (exclude file uploads)
            params = {}
            if request.args:
                params.update(dict(request.args))
            if request.is_json:
                json_data = request.get_json(silent=True) or {}
                # Filter out sensitive fields and file data
                for key, value in json_data.items():
                    if key not in ['password', 'file', 'file_content'] and not isinstance(value, (bytes, bytearray)):
                        params[key] = value

            # Target object hints
            target = request.view_args.copy() if getattr(request, "view_args", None) else {}
            for key in ("id", "document_id", "documentid", "link"):
                if key in request.args and key not in target:
                    target[key] = request.args.get(key)

            app.logger.info(
                "event=api_request method=%s path=%s ip=%s user=%s params=%s target=%s",
                request.method,
                request.path,
                g.client_ip,
                user_ctx,
                params,
                target,
            )

    @app.after_request
    def _log_response(response):
        # Only log responses for API endpoints
        if request.path.startswith('/api/'):
            try:
                user = getattr(g, "user", None)
            except Exception:
                user = None
            user_ctx = {
                "id": (user or {}).get("id") if isinstance(user, dict) else None,
                "login": (user or {}).get("login") if isinstance(user, dict) else None,
            }

            # Calculate response time
            duration_ms = None
            if hasattr(g, 'request_start_time'):
                duration = dt.datetime.utcnow() - g.request_start_time
                duration_ms = int(duration.total_seconds() * 1000)

            app.logger.info(
                "event=api_response status=%s method=%s path=%s ip=%s user=%s duration_ms=%s",
                response.status,
                request.method,
                request.path,
                getattr(g, 'client_ip', 'unknown'),
                user_ctx,
                duration_ms,
            )
        return response

    # Handle Werkzeug HTTP exceptions explicitly to preserve correct status codes (e.g., 404/405)
    @app.errorhandler(HTTPException)
    def _handle_http_exception(e: HTTPException):
        try:
            user = getattr(g, "user", None)
        except Exception:
            user = None
        user_ctx = {
            "id": (user or {}).get("id") if isinstance(user, dict) else None,
            "login": (user or {}).get("login") if isinstance(user, dict) else None,
        }
        client_ip = getattr(g, 'client_ip', 'unknown')
        # Only log API paths to avoid noise
        if request.path.startswith('/api/') or isinstance(e, MethodNotAllowed):
            app.logger.error(
                "event=error user_msg=%s detail=%s", f"{e.name}", str(e)
            )
        # Return JSON with the correct HTTP status code
        return jsonify({"error": e.name}), e.code

    @app.errorhandler(Exception)
    def _log_exception(e):
        # Ensure unhandled exceptions are recorded with user and route context
        try:
            user = getattr(g, "user", None)
        except Exception:
            user = None
        user_ctx = {
            "id": (user or {}).get("id") if isinstance(user, dict) else None,
            "login": (user or {}).get("login") if isinstance(user, dict) else None,
        }
        client_ip = getattr(g, 'client_ip', 'unknown')
        app.logger.exception("event=exception path=%s method=%s ip=%s user=%s", request.path, request.method, client_ip,
                             user_ctx)
        return _safe_error("Internal server error", e, 500)

    try:
        global identity_manager
        # If tests patch IdentityManager to None, avoid calling it
        if IdentityManager is None or RMAP is None:
            raise RuntimeError("RMAP/IdentityManager modules unavailable")

        identity_manager = IdentityManager(
            client_keys_dir=app.config["CLIENT_KEYS_DIR"],
            server_public_key_path=app.config["SERVER_PUB_KEY_PATH"],
            server_private_key_path=app.config["SERVER_PRIV_KEY_PATH"],
            server_private_key_passphrase=app.config["PRIVATE_KEY_PASSPHRASE"],
        )
        global rmap_service
        rmap_service = RMAP(identity_manager)
        app.config["IDENTITY_MANAGER"] = identity_manager
        app.config["RMAP_SERVICE"] = rmap_service
    except FileNotFoundError as e:
        print(f"CRITICAL ERROR: Could not initialize RMAP service. Key files not found at mounted path. {e}")
        rmap_service = None
        app.config["IDENTITY_MANAGER"] = None
        app.config["RMAP_SERVICE"] = None
    except RuntimeError as e:
        # Occurs when IdentityManager or RMAP is None (e.g., during tests)
        app.logger.warning(f"RMAP init skipped: {e}")
        rmap_service = None
        app.config["IDENTITY_MANAGER"] = None
        app.config["RMAP_SERVICE"] = None

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"],
                                      salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def _safe_error(user_msg: str, internal_error: Exception = None, code: int = 500):
        if internal_error:
            app.logger.error("event=error user_msg=%s detail=%s", user_msg, str(internal_error))
        return jsonify({"error": user_msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            client_ip = getattr(g, 'client_ip', 'unknown')
            if not auth.startswith("Bearer "):
                app.logger.info("event=auth_failed reason=missing_bearer method=%s path=%s ip=%s", request.method,
                                request.path, client_ip)
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                app.logger.info("event=auth_failed reason=token_expired method=%s path=%s ip=%s", request.method,
                                request.path, client_ip)
                return _auth_error("Token expired")
            except BadSignature:
                app.logger.info("event=auth_failed reason=invalid_token method=%s path=%s ip=%s", request.method,
                                request.path, client_ip)
                return _auth_error("Invalid token")
            g.user = {
                "id": int(data["uid"]),
                "login": data["login"],
                "email": data.get("email"),
            }
            app.logger.info("event=auth_success user_id=%s login=%s method=%s path=%s ip=%s",
                            g.user["id"], g.user["login"], request.method, request.path, client_ip)
            return f(*args, **kwargs)

        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---

    @app.route("/<path:filename>")
    def static_files(filename):
        try:
            return app.send_static_file(filename)
        except NotFound:
            return jsonify({"error": "File not found"}), 404


    @app.route("/")
    def home():
        try:
            return app.send_static_file("index.html")
        except NotFound:
            return jsonify({"error": "File not found"}), 404

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return (
            jsonify({"message": "The server is up and running.", "db_connected": db_ok}),
            200,
        )

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400
            
        MAX_LOGIN_LEN = 50
        MAX_PASS_LEN = 256
        if len(login) > MAX_LOGIN_LEN:
            return jsonify({"error": f"Login exceeds maximum length of {MAX_LOGIN_LEN} characters"}), 400
        if len(password) > MAX_PASS_LEN:
            return jsonify({"error": f"Password exceeds maximum length of {MAX_PASS_LEN} characters"}), 400

        login = html.escape(login)
        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
            app.logger.info("event=create_user_success user_id=%s email=%s login=%s", uid, email, login)
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            app.logger.error("event=create_user_failed reason=database_error email=%s login=%s error=%s", email, login,
                             str(e))
            return _safe_error("Failed to create user", e, 503)

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            app.logger.error("event=login_failed reason=database_error email=%s error=%s", email, str(e))
            return _safe_error("Login failed", e, 503)

        if not row or not check_password_hash(row.hpassword, password):
            security_monitor.check_login_brute_force(g.client_ip, False)
            return jsonify({"error": "invalid credentials"}), 401

        security_monitor.check_login_brute_force(g.client_ip, True)
        
        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        app.logger.info("event=login_success user_id=%s email=%s login=%s", row.id, email, row.login)
        return (
            jsonify(
                {
                    "token": token,
                    "token_type": "bearer",
                    "expires_in": app.config["TOKEN_TTL_SECONDS"],
                }
            ),
            200,
        )

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        try:
            if "file" not in request.files:
                app.logger.warning("event=upload_document_failed reason=no_file user_id=%s", g.user["id"])
                return jsonify({"error": "file is required (multipart/form-data)"}), 400
            file = request.files["file"]
            if not file or file.filename == "":
                app.logger.warning("event=upload_document_failed reason=empty_filename user_id=%s", g.user["id"])
                return jsonify({"error": "empty filename"}), 400

            fname = file.filename

            # Check file extension
            if not fname.lower().endswith('.pdf'):
                app.logger.warning("event=upload_document_failed reason=invalid_extension filename=%s user_id=%s", fname,
                                   g.user["id"])
                return jsonify({"error": "only PDF files are allowed"}), 400

            # Read file content to validate it's actually a PDF
            file_content = file.read()
            file.seek(0)  # Reset file pointer for later save

            if security_monitor.check_file_upload_attack(g.client_ip, len(file_content), fname):
                app.logger.error(f"SECURITY_BLOCK: File upload attack from IP {g.client_ip}")
                return jsonify({"error": "File upload blocked"}), 400

            # Validate PDF content
            if not is_pdf_bytes(file_content):
                app.logger.warning("event=upload_document_failed reason=invalid_pdf_content filename=%s user_id=%s", fname,
                                   g.user["id"])
                return jsonify({"error": "file does not appear to be a valid PDF"}), 400

            user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
            user_dir.mkdir(parents=True, exist_ok=True)

            ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
            final_name = request.form.get("name") or fname
            stored_name = f"{ts}__{fname}"
            stored_path = user_dir / stored_name
            try:
                file.save(stored_path)
            except Exception as e:
                app.logger.error("event=upload_document_failed reason=file_error filename=%s user_id=%s error=%s",
                                 fname, g.user["id"], str(e))
                return _safe_error("Failed to upload document", e, 500)

            sha_hex = _sha256_file(stored_path)
            size = stored_path.stat().st_size

            try:
                with get_engine().begin() as conn:
                    conn.execute(
                        text(
                            """
                            INSERT INTO Documents (name, path, ownerid, sha256, size)
                            VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                        """
                        ),
                        {
                            "name": final_name,
                            "path": str(stored_path),
                            "ownerid": int(g.user["id"]),
                            "sha256hex": sha_hex,
                            "size": int(size),
                        },
                    )
                    did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                    row = conn.execute(
                        text(
                            """
                            SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                            FROM Documents
                            WHERE id = :id
                        """
                        ),
                        {"id": did},
                    ).one()
                app.logger.info("event=upload_document_success doc_id=%s filename=%s user_id=%s", did, final_name,
                                g.user["id"])
            except Exception as e:
                app.logger.error("event=upload_document_failed reason=database_error filename=%s user_id=%s error=%s",
                                 fname, g.user["id"], str(e))
                return _safe_error("Failed to upload document", e, 503)

            return (
                jsonify(
                    {
                        "id": int(row.id),
                        "name": row.name,
                        "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
                        "sha256": row.sha256_hex,
                        "size": int(row.size),
                    }
                ),
                201,
            )
        except Exception as e:
            app.logger.error(f"File upload processing error: {e}")
            return jsonify({"error": "Failed to process uploaded file. Ensure it is a valid PDF."}), 400

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text(
                        """
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """
                    ),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            app.logger.error("event=list_documents_failed user_id=%s error=%s", g.user["id"], str(e))
            return _safe_error("Failed to list documents", e, 503)

        docs = [
            {
                "id": int(r.id),
                "name": r.name,
                "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
                "sha256": r.sha256_hex,
                "size": int(r.size),
            }
            for r in rows
        ]
        app.logger.info("event=list_documents_success user_id=%s count=%d", g.user["id"], len(rows))
        return jsonify({"documents": docs}), 200

    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text(
                        """
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """
                    ),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            return _safe_error("Failed to list versions", e, 503)

        versions = [
            {
                "id": int(r.id),
                "documentid": int(r.documentid),
                "link": r.link,
                "intended_for": r.intended_for,
                "secret": r.secret,
                "method": r.method,
            }
            for r in rows
        ]
        return jsonify({"versions": versions}), 200

    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text(
                        """
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """
                    ),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return _safe_error("Failed to list all versions", e, 503)

        versions = [
            {
                "id": int(r.id),
                "documentid": int(r.documentid),
                "link": r.link,
                "intended_for": r.intended_for,
                "method": r.method,
            }
            for r in rows
        ]
        return jsonify({"versions": versions}), 200

    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """
                    ),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            app.logger.error("event=get_document_failed reason=database_error doc_id=%s user_id=%s error=%s",
                             document_id, g.user["id"], str(e))
            return _safe_error("Failed to get document", e, 503)

        # Don't leak whether a doc exists for another user
        if not row:
            app.logger.info("event=get_document_failed reason=not_found doc_id=%s user_id=%s", document_id,
                            g.user["id"])
            return jsonify({"error": "document not found"}), 404

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            storage_root = Path(cast(str, app.config["STORAGE_DIR"]))
            file_path = _safe_resolve_under_storage(row.path, storage_root)
        except Exception as e:
            # Path looks suspicious or outside storage
            app.logger.error("event=get_document_failed reason=path_security doc_id=%s user_id=%s error=%s",
                             document_id, g.user["id"], str(e))
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            app.logger.error("event=get_document_failed reason=file_missing doc_id=%s user_id=%s path=%s",
                             document_id, g.user["id"], str(file_path))
            return jsonify({"error": "file missing on disk"}), 410

        app.logger.info("event=get_document_success doc_id=%s filename=%s user_id=%s",
                        document_id, row.name, g.user["id"])
        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,  # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """
                    ),
                    {"link": link},
                ).first()
        except Exception as e:
            app.logger.error("event=get_version_failed reason=database_error link=%s error=%s", link, str(e))
            return _safe_error("Failed to get version", e, 503)

        if not row:
            security_monitor.check_watermark_link_brute_force(g.client_ip, 404)
            return jsonify({"error": "document not found"}), 404

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            storage_root = Path(cast(str, app.config["STORAGE_DIR"]))
            file_path = _safe_resolve_under_storage(row.path, storage_root)
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            app.logger.error("event=get_version_failed reason=file_missing link=%s user_id=%s", link, g.user["id"])
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,  # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                    request.args.get("id")
                    or request.args.get("documentid")
                    or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        # Fetch the document (enforce ownership)
        try:
            with get_engine().connect() as conn:
                query = "SELECT * FROM Documents WHERE id = :id AND ownerid = :uid"
                row = conn.execute(
                    text(query),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            app.logger.error("event=delete_document_failed reason=database_error doc_id=%s user_id=%s error=%s",
                             doc_id, g.user["id"], str(e))
            return _safe_error("Failed to delete document", e, 503)

        if not row:
            # Don't reveal others' docs—just say not found
            app.logger.warning("event=delete_document_failed reason=not_found doc_id=%s user_id=%s", doc_id,
                               g.user["id"])
            return jsonify({"error": "document not found"}), 404

        # Delete version files first (if exist) before deleting original file
        storage_root = Path(cast(str, app.config["STORAGE_DIR"]))
        try:
            with get_engine().connect() as conn:
                versions = conn.execute(
                    text("SELECT path FROM Versions WHERE documentid = :id"),
                    {"id": doc_id},
                ).fetchall()
        except Exception as e:
            return _safe_error("Failed to delete document", e, 503)

        # Resolve and delete original file and version files (best effort)
        file_deleted = False
        file_missing = False
        has_delete_issues = False
        try:
            for version in versions:
                version_path = _safe_resolve_under_storage(version.path, storage_root)
                if version_path.exists():
                    try:
                        version_path.unlink()
                    except Exception as e:
                        has_delete_issues = True
                        app.logger.error(
                            "event=delete_document_failed reason=version_file_delete_error version_path=%s version_id=%s error=%s",
                            version_path, version.id, e)

            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    has_delete_issues = True
                    app.logger.error(
                        "event=delete_document_failed reason=file_delete_error file_path=%s doc_id=%s error=%s", fp,
                        row.id, e)

            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            has_delete_issues = True
            app.logger.error("event=delete_document_failed reason=path_security_violation error=%s", e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on Version.documentid,
                # uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"), {"id": doc_id})
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
            app.logger.info(
                "event=delete_document_success doc_id=%s user_id=%s file_deleted=%s file_missing=%s has_issues=%s",
                doc_id, g.user["id"], file_deleted, file_missing, has_delete_issues)
        except Exception as e:
            app.logger.error("event=delete_document_failed reason=database_error doc_id=%s user_id=%s error=%s",
                             doc_id, g.user["id"], str(e))
            return _safe_error("Failed to delete document", e, 503)

        return (
            jsonify(
                {
                    "deleted": True,
                    "id": doc_id,
                    "file_deleted": file_deleted,
                    "file_missing": file_missing,
                    "has_file_issues": has_delete_issues,  # boolean flag instead of error details
                }
            ),
            200,
        )

    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on GET
        if not document_id:
            document_id = (
                    request.args.get("id")
                    or request.args.get("documentid")
                    or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            app.logger.warning("event=create_watermark_failed reason=missing_fields doc_id=%s user_id=%s", doc_id,
                               g.user["id"])
            return (
                jsonify({"error": "method, intended_for, secret, and key are required"}),
                400,
            )

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            app.logger.error("event=create_watermark_failed reason=database_error doc_id=%s user_id=%s error=%s",
                             doc_id, g.user["id"], str(e))
            return _safe_error("Failed to create watermark", e, 503)

        if not row:
            app.logger.warning("event=create_watermark_failed reason=document_not_found doc_id=%s user_id=%s", doc_id,
                               g.user["id"])
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(cast(str, app.config["STORAGE_DIR"])).resolve()
        try:
            file_path = _safe_resolve_under_storage(row.path, storage_root)
            app.logger.info("event=create_watermark_attempt doc_id=%s method=%s intended_for=%s user_id=%s path=%s",
                            doc_id, method, intended_for, g.user["id"], file_path)
        except RuntimeError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(method=method, pdf=str(file_path), position=position)
            if applicable is False:
                app.logger.warning("event=create_watermark_failed reason=method_not_applicable doc_id=%s user_id=%s",
                                   doc_id, g.user["id"])
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            app.logger.error("event=create_watermark_failed reason=exception doc_id=%s user_id=%s error=%s",
                             doc_id, g.user["id"], str(e))
            return _safe_error("Watermark method not supported for this document", e, 400)

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position,
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            app.logger.error("event=create_watermark_failed reason=exception doc_id=%s user_id=%s error=%s",
                             doc_id, g.user["id"], str(e))
            return _safe_error("Failed to apply watermark", e, 500)

        # build destination file name: "<original_name>__<method_name>__<intended_to>__<timestamp>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        method_name = secure_filename(method)
        timestamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{method_name}__{intended_slug}__{timestamp}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return _safe_error("Failed to save watermarked document", e, 500)

        timestamp = dt.datetime.utcnow().isoformat()
        random_part = secrets.token_hex(16)
        link_token = hashlib.sha256(f"{candidate}_{timestamp}_{random_part}".encode("utf-8")).hexdigest()

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """
                    ),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": dest_path,
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
            app.logger.info(
                "event=create_watermark_success doc_id=%s version_id=%s method=%s intended_for=%s link=%s user_id=%s",
                doc_id, vid, method, intended_for, link_token, g.user["id"])
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return _safe_error("Failed to create watermark", e, 503)

        return (
            jsonify(
                {
                    "id": vid,
                    "documentid": doc_id,
                    "link": link_token,
                    "intended_for": intended_for,
                    "method": method,
                    "position": position,
                    "filename": candidate,
                    "size": len(wm_bytes),
                }
            ),
            201,
        )

    # @app.post("/api/load-plugin")
    # @require_auth
    # def load_plugin():
    #     """
    #     Load a serialized Python class implementing WatermarkingMethod from
    #     STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it in wm_mod.METHODS.
    #     Body: { "filename": "MyMethod.pkl", "overwrite": false }
    #     """
    #     payload = request.get_json(silent=True) or {}
    #     filename = (payload.get("filename") or "").strip()
    #     # overwrite = bool(payload.get("overwrite", False))
    #
    #     if not filename:
    #         return jsonify({"error": "filename is required"}), 400
    #
    #     # Locate the plugin in /storage/files/plugins (relative to STORAGE_DIR)
    #     storage_root = Path(cast(str, app.config["STORAGE_DIR"]))
    #     plugins_dir = storage_root / "files" / "plugins"
    #     try:
    #         plugins_dir.mkdir(parents=True, exist_ok=True)
    #         plugin_path = plugins_dir / filename
    #     except Exception as e:
    #         return jsonify({"error": f"plugin path error: {e}"}), 500
    #
    #     if not plugin_path.exists():
    #         return jsonify({"error": f"plugin file not found: {filename}"}), 404
    #
    #     # Unpickle the object (dill if available; else std pickle)
    #     try:
    #         with plugin_path.open("rb") as f:
    #             obj = _pickle.load(f)
    #     except Exception as e:
    #         return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400
    #
    #     # Accept: class object, or instance (we'll promote instance to its class)
    #     if isinstance(obj, type):
    #         cls = obj
    #     else:
    #         cls = obj.__class__
    #
    #     # Determine method name for registry
    #     method_name = getattr(cls, "name", getattr(cls, "__name__", None))
    #     if not method_name or not isinstance(method_name, str):
    #         return (
    #             jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}),
    #             400,
    #         )
    #
    #     # Validate interface: either subclass of WatermarkingMethod or duck-typing
    #     has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
    #     if WatermarkingMethod is not None:
    #         is_ok = issubclass(cls, WatermarkingMethod) and has_api
    #     else:
    #         is_ok = has_api
    #     if not is_ok:
    #         return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400
    #
    #     # Register the class (not an instance) so you can instantiate as needed later
    #     WMUtils.METHODS[method_name] = cls()
    #
    #     return (
    #         jsonify(
    #             {
    #                 "loaded": True,
    #                 "filename": filename,
    #                 "registered_as": method_name,
    #                 "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
    #                 "methods_count": len(WMUtils.METHODS),
    #             }
    #         ),
    #         201,
    #     )

    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})

        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark-by-link/
    @app.post("/api/read-watermark-by-link/<link>")
    @require_auth
    def read_watermark_by_link(link: str | None = None):
        if not link:
            link = (
                    request.args.get("link")
                    or (request.is_json and (request.get_json(silent=True) or {}).get("link"))
            )
        try:
            specific_link = link
        except (TypeError, ValueError):
            return jsonify({"error": "watermarked version link required"}), 400

        """Read watermark from a specific watermarked version by link (requires authentication)."""
        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        if not method or not key or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT v.id, v.documentid, v.link, v.secret, v.path
                        FROM Versions v
                        JOIN Documents d ON d.id = v.documentid
                        WHERE v.link = :link AND d.ownerid = :uid
                        LIMIT 1
                    """
                    ),
                    {"link": specific_link, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            app.logger.error("event=read_watermark_by_link_failed reason=database_error link=%s user_id=%s error=%s",
                             specific_link, g.user["id"], str(e))
            return _safe_error("Failed to read watermark by link", e, 503)

        if not row:
            app.logger.warning("event=read_watermark_by_link_failed reason=not_found link=%s user_id=%s",
                               specific_link, g.user["id"])
            return jsonify({"error": "watermarked version not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(cast(str, app.config["STORAGE_DIR"])).resolve()
        try:
            file_path = _safe_resolve_under_storage(row.path, storage_root)
            app.logger.info("event=read_watermark_by_link_attempt link=%s user_id=%s path=%s",
                            specific_link, g.user["id"], file_path)
        except RuntimeError as e:
            app.logger.error("event=read_watermark_by_link_failed reason=path_invalid link=%s user_id=%s error=%s",
                             specific_link, g.user["id"], str(e))
            return jsonify({"error": "watermarked version path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "watermarked version missing on disk"}), 410

        # read watermark from the watermarked version file
        secret = None
        try:
            secret = WMUtils.read_watermark(method=method, pdf=str(file_path), key=key)
        except Exception as e:
            app.logger.error("event=read_watermark_by_link_failed reason=exception link=%s user_id=%s error=%s",
                             specific_link, g.user["id"], str(e))
            return _safe_error("Failed to read watermark from watermarked version", e, 400)

        if secret != row.secret:
            app.logger.error("event=read_watermark_by_link_failed reason=secret_mismatch link=%s user_id=%s",
                             specific_link, g.user["id"])
            return jsonify({"error": "Failed to read watermark from watermarked version"}), 400

        app.logger.info("event=read_watermark_by_link_success link=%s user_id=%s",
                        specific_link, g.user["id"])
        return jsonify({
            "link": link,
            "secret": secret,
            "method": method,
            "position": position
        }), 200

    def get_rmap_source_document() -> tuple[int, str]:
        """
        Get the RMAP source document from the database.

        The system user (rmap_system) should have exactly one document uploaded,
        which serves as the source for all watermarked distributions.

        Returns:
            tuple: (document_id, document_path)

        Raises:
            RuntimeError: If no document found or multiple documents found
        """
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text(
                        """
                        SELECT id, path FROM Documents 
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                        """
                    ),
                    {"uid": app.config["RMAP_SYSTEM_USER_ID"]}
                ).fetchall()

                if not rows:
                    raise RuntimeError(
                        f"No source document found for RMAP system user (ID={app.config['RMAP_SYSTEM_USER_ID']}). "
                        f"Please upload a document using the rmap_system account first."
                    )

                if len(rows) > 1:
                    app.logger.warning(
                        "event=get_rmap_source_document_warning reason=multiple_documents count=%d system_user_id=%s",
                        len(rows), app.config["RMAP_SYSTEM_USER_ID"])

                doc_id = int(rows[0].id)
                doc_path = rows[0].path

                # Verify file exists
                file_path = Path(doc_path)
                if not file_path.exists():
                    raise RuntimeError(
                        f"RMAP source document file not found: {doc_path}. "
                        f"Document ID: {doc_id}"
                    )

                return doc_id, doc_path

        except Exception as e:
            app.logger.error("event=get_rmap_source_document_failed reason=exception error=%s", str(e))
            raise

    @app.route('/api/rmap-initiate', methods=['POST'])
    @app.route('/rmap-initiate', methods=['POST'])
    def rmap_initiate():
        if rmap_service is None:
            app.logger.error("event=rmap_initiate_failed reason=service_unavailable" )
            return jsonify({"error": "RMAP service is not configured or unavailable"}), 503

        data = request.get_json()
        if not data or 'payload' not in data:
            return jsonify({"error": "Payload missing"}), 400

        # Log the request to establish a session
        try:
            decrypted_data = identity_manager.decrypt_for_server(data['payload'])
            app.logger.info("event=rmap_initiate_success identity=%s", decrypted_data['identity'])

            response = rmap_service.handle_message1(data)
            if "error" in response:
                security_monitor.check_rmap_attack(g.client_ip, False, response['error'])
                app.logger.error("event=rmap_initiate_failed reason=error in response error=%s", response['error'])
                return jsonify({"error": response['error']}), 400
            else:
                security_monitor.check_rmap_attack(g.client_ip, True)
                return response, 200
        except Exception as e:
            app.logger.error(f"RMAP initiate_transfer failed: {e}")
            return jsonify({"error": "RMAP service communication failed"}), 503

    @app.route('/api/rmap-get-link', methods=['POST'])
    @app.route('/rmap-get-link', methods=['POST'])
    def rmap_get_link():
        if rmap_service is None:
            app.logger.error("event=rmap_get_link_failed reason=service_unavailable")
            return jsonify({"error": "RMAP service not available"}), 503

        data = request.get_json()
        if not data or 'payload' not in data:
            return jsonify({"error": "Payload missing"}), 400

        try:
            # Session verification
            decrypted_data = identity_manager.decrypt_for_server(data['payload'])
            sender_identity = rmap_service._find_identity_by_nonce_server(decrypted_data['nonceServer'])
            app.logger.info("event=rmap_get_link_decrypt sender_identity=%s", sender_identity)
            if sender_identity is None or sender_identity not in rmap_service.nonces:
                app.logger.warning("event=rmap_get_link_failed reason=invalid_session identity=%s", sender_identity)
                return jsonify({"error": "Invalid session or nonce mismatch"}), 401

            # Verify watermarked document exists
            try:
                rmap_doc_id, source_pdf_path = get_rmap_source_document()
            except Exception as e:
                app.logger.error("event=rmap_get_link_failed reason=failed_to_access_rmap_source_document error=%s",
                                 str(e))
                return _safe_error("Failed to access RMAP source document", e, 503)

            try:
                with get_engine().begin() as conn:
                    row = conn.execute(
                        text(
                            """
                            SELECT *
                            FROM Versions
                            WHERE intended_for = :intended_for
                            AND documentid = :documentid
                            LIMIT 1
                        """
                        ),
                        {"intended_for": sender_identity, "documentid": rmap_doc_id},
                    ).first()
            except Exception as e:
                app.logger.error("event=rmap_get_link_failed reason=database_error error=%s sender_identity=%s", str(e),
                                 sender_identity)
                return _safe_error("Failed to get version", e, 503)

            if not row:
                response_data = rmap_service.handle_message2(data)
                if "error" in response_data:
                    app.logger.error(
                        "event=rmap_get_link_failed reason=error in response_data error=%s sender_identity=%s",
                        response_data['error'], sender_identity)
                    return jsonify({"error": response_data['error']}), 400
                else:
                    secret_link = response_data['result']

                try:
                    watermarked_bytes = WMUtils.apply_watermark(
                        method=app.config["WATERMARK_METHOD"],
                        pdf=source_pdf_path,
                        secret=sender_identity,
                        key=app.config["WATERMARK_KEY"],
                        position=None
                    )

                    if not isinstance(watermarked_bytes, (bytes, bytearray)) or len(watermarked_bytes) == 0:
                        return _safe_error("Watermarking produced no output", code=500)

                except Exception as e:
                    app.logger.error(
                        "event=rmap_get_link_failed reason=failed_to_apply_watermark error=%s, sender_identity=%s",
                        str(e), sender_identity)
                    return _safe_error("Failed to apply watermark", e, 500)

                storage_dir = Path(app.config["STORAGE_DIR"]) / "rmap_versions"
                storage_dir.mkdir(parents=True, exist_ok=True)

                timestamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
                identity_slug = secure_filename(sender_identity)
                filename = f"rmap__{identity_slug}__{timestamp}.pdf"
                dest_path = storage_dir / filename

                try:
                    with dest_path.open("wb") as f:
                        f.write(watermarked_bytes)
                except Exception as e:
                    return _safe_error("Failed to save watermarked document", e, 500)

                try:
                    with get_engine().begin() as conn:
                        conn.execute(
                            text(
                                """
                                INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                                VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                                """
                            ),
                            {
                                "documentid": rmap_doc_id,
                                "link": secret_link,
                                "intended_for": sender_identity,
                                "secret": sender_identity,
                                "method": app.config["WATERMARK_METHOD"],
                                "position": "",
                                "path": str(dest_path),
                            },
                        )
                except Exception as e:
                    try:
                        dest_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    app.logger.error(
                        "event=rmap_get_link_failed reason=failed_to_record_watermarked_version error=%s sender_identity=%s",
                        str(e), sender_identity)
                    return _safe_error("Failed to record watermarked version", e, 503)

                app.logger.info(
                    "event=rmap-get-link phase=generated identity=%s link=%s",
                    sender_identity,
                    secret_link,
                )
                del rmap_service.nonces[sender_identity]
                return response_data, 200
            else:
                del rmap_service.nonces[sender_identity]
                app.logger.info(
                    "event=rmap-get-link phase=existing identity=%s link=%s",
                    sender_identity,
                    row.link,
                )
                return jsonify({"result": row.link}), 200


        except Exception as e:
            app.logger.error("event=rmap-get-link error=%s", str(e))
            return jsonify({"error": "Invalid session or nonce mismatch"}), 400

    @app.route('/api/rmap-identify-leak', methods=['POST'])
    def rmap_identify_leak():
        try:
            admin_key = request.headers.get('X-Admin-Key') or request.form.get('admin_key')
            if not admin_key or admin_key != app.config["RMAP_ADMIN_KEY"]:
                security_monitor.check_admin_access_attack(g.client_ip, False)
                app.logger.warning("event=rmap_identify_leak_failed reason=unauthorized")
                return jsonify({"error": "Unauthorized: Invalid or missing admin key"}), 401
            else:
                security_monitor.check_admin_access_attack(g.client_ip, True)

            if 'file' not in request.files:
                return jsonify({"error": "file is required (multipart/form-data)"}), 400

            file = request.files['file']
            if not file:
                return jsonify({"error": "empty filename"}), 400

            try:
                file_content = file.read()
            except Exception as e:
                return _safe_error("Failed to read uploaded file", e, 400)

            try:
                extracted_secret = WMUtils.read_watermark(
                    method=app.config["WATERMARK_METHOD"],
                    pdf=file_content,
                    key=app.config["WATERMARK_KEY"]
                )
                app.logger.info("event=rmap_identify_leak_watermark_extracted secret=%s", extracted_secret)
            except Exception as e:
                app.logger.warning("event=rmap_identify_leak_failed reason=watermark_extraction_failed error=%s", str(e))
                return jsonify({
                    "identified": False,
                    "error": "No watermark found or watermark extraction failed"
                }), 200

            try:
                with get_engine().connect() as conn:
                    row = conn.execute(
                        text(
                            """
                            SELECT id, link, intended_for, secret, method, path
                            FROM Versions
                            WHERE secret = :secret AND method = :method
                            LIMIT 1
                            """
                        ),
                        {"secret": extracted_secret, "method": app.config["WATERMARK_METHOD"]},
                    ).first()
            except Exception as e:
                app.logger.error("event=rmap_identify_leak_failed reason=database_error error=%s", str(e))
                return _safe_error("Failed to query database", e, 503)

            if not row:
                app.logger.info("event=rmap_identify_leak_not_found secret=%s", extracted_secret)
                return jsonify({
                    "identified": False,
                    "extracted_secret": extracted_secret,
                    "error": "Watermark extracted but no matching version found in database"
                }), 200

            app.logger.info("event=rmap_identify_leak_success identity=%s version_id=%s link=%s",
                            row.intended_for, row.id, row.link)
            return jsonify({
                "identified": True,
                "identity": row.intended_for,
                "extracted_secret": extracted_secret,
                "method": row.method,
                "version_info": {
                    "id": int(row.id),
                    "link": row.link,
                    "intended_for": row.intended_for,
                    "path": row.path
                }
            }), 200
        except Exception as e:
            app.logger.error(f"rmap_identify_leak failed: {e}")
            return jsonify({"error": "RMAP identify leak service communication failed"}), 503

    # GET /api/security-status 
    @app.get("/api/security-status")
    def security_status():
        admin_key = request.headers.get('X-Admin-Key')
        if not admin_key or admin_key != app.config["RMAP_ADMIN_KEY"]:
            security_monitor.check_admin_access_attack(g.client_ip, False)
            return jsonify({"error": "Unauthorized: Invalid or missing admin key"}), 401
        
        security_monitor.check_admin_access_attack(g.client_ip, True)
        summary = security_monitor.get_security_summary()
        return jsonify({
            "security_summary": summary,
            "timestamp": dt.datetime.utcnow().isoformat()
        }), 200
    
    @app.route('/api/security-recover', methods=['POST'])
    def security_recover():
        """Recover from attacks - clear suspicious IPs and reset counters"""
        admin_key = request.headers.get('X-Admin-Key')
        if not admin_key or admin_key != app.config["RMAP_ADMIN_KEY"]:
            security_monitor.check_admin_access_attack(g.client_ip, False)
            return jsonify({"error": "Unauthorized: Invalid or missing admin key"}), 401
        
        security_monitor.check_admin_access_attack(g.client_ip, True)
        
        data = request.get_json() or {}
        ip = data.get('ip')
        attack_type = data.get('attack_type')
        
        recovery_result = security_monitor.recover_from_attack(ip, attack_type)
        
        app.logger.info(
            "event=security_recovery_request ip=%s attack_type=%s actions=%s",
            g.client_ip, attack_type, "; ".join(recovery_result['recovery_actions'])
        )
        
        return jsonify({
            "recovery_result": recovery_result,
            "timestamp": dt.datetime.utcnow().isoformat()
        })
    
    @app.route('/api/security-incidents', methods=['GET'])
    def security_incidents():
        """Get attack incidents for analysis"""
        admin_key = request.headers.get('X-Admin-Key')
        if not admin_key or admin_key != app.config["RMAP_ADMIN_KEY"]:
            security_monitor.check_admin_access_attack(g.client_ip, False)
            return jsonify({"error": "Unauthorized: Invalid or missing admin key"}), 401
        
        security_monitor.check_admin_access_attack(g.client_ip, True)
        
        limit = request.args.get('limit', 50, type=int)
        incidents = security_monitor.get_attack_incidents(limit)
        
        return jsonify({
            "incidents": incidents,
            "total_count": len(incidents),
            "timestamp": dt.datetime.utcnow().isoformat()
        })
    
    @app.route('/api/security-analysis', methods=['GET'])
    def security_analysis():
        """Analyze attack patterns for recovery planning"""
        admin_key = request.headers.get('X-Admin-Key')
        if not admin_key or admin_key != app.config["RMAP_ADMIN_KEY"]:
            security_monitor.check_admin_access_attack(g.client_ip, False)
            return jsonify({"error": "Unauthorized: Invalid or missing admin key"}), 401
        
        security_monitor.check_admin_access_attack(g.client_ip, True)
        
        analysis = security_monitor.analyze_attack_patterns()
        
        return jsonify({
            "analysis": analysis,
            "timestamp": dt.datetime.utcnow().isoformat()
        })

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
