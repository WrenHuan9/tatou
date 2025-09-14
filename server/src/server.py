import os
from dotenv import load_dotenv
import io
import hashlib
import datetime as dt
from pathlib import Path
from functools import wraps
import inspect

from flask import Flask, jsonify, request, g, send_file, Response, current_app
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

import pickle as _std_pickle
try:
    import dill as _pickle
except Exception:
    _pickle = _std_pickle

# 确保内部导入路径正确
from server.src import watermarking_utils as WMUtils
from server.src.watermarking_method import WatermarkingMethod, WatermarkingError, InvalidKeyError, SecretNotFoundError

load_dotenv()


# --- 数据库和核心辅助函数 (全部移至顶层) ---

def db_url() -> str:
    """生成数据库连接URL"""
    return (
        f"mysql+pymysql://{current_app.config['DB_USER']}:{current_app.config['DB_PASSWORD']}"
        f"@{current_app.config['DB_HOST']}:{current_app.config['DB_PORT']}/{current_app.config['DB_NAME']}?charset=utf8mb4"
    )

def get_engine():
    """获取数据库引擎实例"""
    eng = current_app.config.get("_ENGINE")
    if eng is None:
        eng = create_engine(db_url(), pool_pre_ping=True, future=True)
        current_app.config["_ENGINE"] = eng
    return eng

def _serializer():
    """创建用于生成和验证token的序列化器"""
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="tatou-auth")

def _auth_error(msg: str, code: int = 401):
    """返回一个标准的认证错误响应"""
    return jsonify({"error": msg}), code

def require_auth(f):
    """一个要求用户认证的装饰器"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return _auth_error("Missing or invalid Authorization header")
        token = auth.split(" ", 1)[1].strip()
        try:
            data = _serializer().loads(token, max_age=current_app.config["TOKEN_TTL_SECONDS"])
        except SignatureExpired:
            return _auth_error("Token expired")
        except BadSignature:
            return _auth_error("Invalid token")
        g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
        return f(*args, **kwargs)
    return wrapper

def _sha256_file(path: Path) -> str:
    """计算文件的SHA256哈希值"""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
    """安全地解析路径，确保它在指定的存储根目录内"""
    storage_root = storage_root.resolve()
    fp = Path(p)
    if not fp.is_absolute():
        fp = storage_root / fp
    fp = fp.resolve()
    # 使用 a.is_relative_to(b) (Python 3.9+)
    try:
        fp.relative_to(storage_root)
    except ValueError:
        raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
    return fp


# --- 应用工厂函数 ---
def create_app(test_config=None):
    app = Flask(__name__)

    # --- Config ---
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        STORAGE_DIR=Path(os.environ.get("STORAGE_DIR", "./storage")).resolve(),
        TOKEN_TTL_SECONDS=int(os.environ.get("TOKEN_TTL_SECONDS", "86400")),
        DB_USER=os.environ.get("DB_USER", "tatou"),
        DB_PASSWORD=os.environ.get("DB_PASSWORD", "tatou"),
        DB_HOST=os.environ.get("DB_HOST", "db"),
        DB_PORT=int(os.environ.get("DB_PORT", "3306")),
        DB_NAME=os.environ.get("DB_NAME", "tatou"),
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        raise ValueError("No SECRET_KEY set for the application. Please set it as an environment variable.")

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=True
    )

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)
    csrf = CSRFProtect(app)

    # --- 在 app context 内部注册路由和请求处理器 ---
    with app.app_context():
        @app.after_request
        def add_security_headers(response: Response):
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            return response

        # --- Routes ---
        @app.route("/<path:filename>")
        def static_files(filename):
            return app.send_static_file(filename)

        @app.route("/")
        def home():
            return app.send_static_file("index.html")

        @app.get("/healthz")
        def healthz():
            try:
                with get_engine().connect() as conn:
                    conn.execute(text("SELECT 1"))
                db_ok = True
            except Exception:
                db_ok = False
            return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

        @app.post("/api/create-user")
        def create_user():
            payload = request.get_json(silent=True) or {}
            email = (payload.get("email") or "").strip().lower()
            login = (payload.get("login") or "").strip()
            password = payload.get("password") or ""
            if not email or not login or not password:
                return jsonify({"error": "email, login, and password are required"}), 400
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
            except IntegrityError:
                return jsonify({"error": "email or login already exists"}), 409
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

        @app.post("/api/login")
        def login():
            payload = request.get_json(silent=True) or {}
            login_user = (payload.get("login") or "").strip()
            password = payload.get("password") or ""
            if not login_user or not password:
                return jsonify({"error": "login and password are required"}), 400
            try:
                with get_engine().connect() as conn:
                    row = conn.execute(
                        text("SELECT id, email, login, hpassword FROM Users WHERE login = :login LIMIT 1"),
                        {"login": login_user},
                    ).first()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            if not row or not check_password_hash(row.hpassword, password):
                return jsonify({"error": "invalid credentials"}), 401
            token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
            return jsonify({"token": token, "token_type": "bearer", "expires_in": current_app.config["TOKEN_TTL_SECONDS"]}), 200

        @app.post("/api/upload-document")
        @require_auth
        def upload_document():
            if "file" not in request.files:
                return jsonify({"error": "file is required (multipart/form-data)"}), 400
            file = request.files["file"]
            if not file or file.filename == "":
                return jsonify({"error": "empty filename"}), 400
            fname = file.filename
            user_dir = current_app.config["STORAGE_DIR"] / "files" / g.user["login"]
            user_dir.mkdir(parents=True, exist_ok=True)
            ts = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
            final_name = request.form.get("name") or fname
            stored_name = f"{ts}__{fname}"
            stored_path = user_dir / stored_name
            file.save(stored_path)
            sha_hex = _sha256_file(stored_path)
            size = stored_path.stat().st_size
            try:
                with get_engine().begin() as conn:
                    conn.execute(
                        text("INSERT INTO Documents (name, path, ownerid, sha256, size) VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)"),
                        {"name": final_name, "path": str(stored_path), "ownerid": int(g.user["id"]), "sha256hex": sha_hex, "size": int(size)},
                    )
                    did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                    row = conn.execute(
                        text("SELECT id, name, creation, HEX(sha256) AS sha256_hex, size FROM Documents WHERE id = :id"),
                        {"id": did},
                    ).one()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            return jsonify({
                "id": int(row.id), "name": row.name,
                "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
                "sha256": row.sha256_hex, "size": int(row.size),
            }), 201

        @app.get("/api/list-documents")
        @require_auth
        def list_documents():
            try:
                with get_engine().connect() as conn:
                    rows = conn.execute(
                        text("SELECT id, name, creation, HEX(sha256) AS sha256_hex, size FROM Documents WHERE ownerid = :uid ORDER BY creation DESC"),
                        {"uid": int(g.user["id"])},
                    ).all()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            docs = [{"id": int(r.id), "name": r.name, "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation), "sha256": r.sha256_hex, "size": int(r.size)} for r in rows]
            return jsonify({"documents": docs}), 200

        @app.get("/api/list-versions")
        @app.get("/api/list-versions/<int:document_id>")
        @require_auth
        def list_versions(document_id: int | None = None):
            if document_id is None:
                document_id = request.args.get("id") or request.args.get("documentid")
                try:
                    document_id = int(document_id)
                except (TypeError, ValueError):
                    return jsonify({"error": "document id required"}), 400
            try:
                with get_engine().connect() as conn:
                    rows = conn.execute(
                        text("SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method FROM Users u JOIN Documents d ON d.ownerid = u.id JOIN Versions v ON d.id = v.documentid WHERE u.login = :glogin AND d.id = :did"),
                        {"glogin": str(g.user["login"]), "did": document_id},
                    ).all()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            versions = [{"id": int(r.id), "documentid": int(r.documentid), "link": r.link, "intended_for": r.intended_for, "secret": r.secret, "method": r.method} for r in rows]
            return jsonify({"versions": versions}), 200

        @app.get("/api/list-all-versions")
        @require_auth
        def list_all_versions():
            try:
                with get_engine().connect() as conn:
                    rows = conn.execute(
                        text("SELECT v.id, v.documentid, v.link, v.intended_for, v.method FROM Users u JOIN Documents d ON d.ownerid = u.id JOIN Versions v ON d.id = v.documentid WHERE u.login = :glogin"),
                        {"glogin": str(g.user["login"])},
                    ).all()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            versions = [{"id": int(r.id), "documentid": int(r.documentid), "link": r.link, "intended_for": r.intended_for, "method": r.method} for r in rows]
            return jsonify({"versions": versions}), 200

        @app.get("/api/get-document")
        @app.get("/api/get-document/<int:document_id>")
        @require_auth
        def get_document(document_id: int | None = None):
            if document_id is None:
                document_id = request.args.get("id") or request.args.get("documentid")
                try:
                    document_id = int(document_id)
                except (TypeError, ValueError):
                    return jsonify({"error": "document id required"}), 400
            try:
                with get_engine().connect() as conn:
                    row = conn.execute(
                        text("SELECT id, name, path, HEX(sha256) AS sha256_hex, size FROM Documents WHERE id = :id AND ownerid = :uid LIMIT 1"),
                        {"id": document_id, "uid": int(g.user["id"])},
                    ).first()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            if not row:
                return jsonify({"error": "document not found"}), 404
            file_path = Path(row.path)
            try:
                file_path.resolve().relative_to(current_app.config["STORAGE_DIR"].resolve())
            except Exception:
                return jsonify({"error": "document path invalid"}), 500
            if not file_path.exists():
                return jsonify({"error": "file missing on disk"}), 410
            resp = send_file(
                file_path, mimetype="application/pdf", as_attachment=False,
                download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
                conditional=True, max_age=0, last_modified=file_path.stat().st_mtime,
            )
            if isinstance(row.sha256_hex, str) and row.sha256_hex:
                resp.set_etag(row.sha256_hex.lower())
            resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
            return resp

        @app.get("/api/get-version/<link>")
        def get_version(link: str):
            try:
                with get_engine().connect() as conn:
                    row = conn.execute(text("SELECT * FROM Versions WHERE link = :link LIMIT 1"), {"link": link}).first()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            if not row:
                return jsonify({"error": "document not found"}), 404
            file_path = Path(row.path)
            try:
                file_path.resolve().relative_to(current_app.config["STORAGE_DIR"].resolve())
            except Exception:
                return jsonify({"error": "document path invalid"}), 500
            if not file_path.exists():
                return jsonify({"error": "file missing on disk"}), 410
            resp = send_file(
                file_path, mimetype="application/pdf", as_attachment=False,
                download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
                conditional=True, max_age=0, last_modified=file_path.stat().st_mtime,
            )
            resp.headers["Cache-Control"] = "private, max-age=0"
            return resp

        # 请将 server/src/server.py 中的 delete_document 函数替换为这个版本

        @app.route("/api/delete-document", methods=["DELETE", "POST"])
        @app.route("/api/delete-document/<int:document_id>", methods=["DELETE"])
        @require_auth
        def delete_document(document_id: int | None = None):
            if not document_id:
                document_id = (request.args.get("id") or request.args.get("documentid") or (
                            request.is_json and (request.get_json(silent=True) or {}).get("id")))
            try:
                doc_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

            try:
                with get_engine().connect() as conn:
                    # 关键修复1：不再使用 SELECT *，只选择我们需要的 id 和 path 列
                    row = conn.execute(
                        text("SELECT id, path FROM Documents WHERE id = :id AND ownerid = :uid"),
                        {"id": doc_id, "uid": int(g.user["id"])}
                    ).first()
            except Exception as e:
                return jsonify({"error": f"database error during select: {str(e)}"}), 503

            if not row:
                return jsonify({"error": "document not found"}), 404

            storage_root = Path(current_app.config["STORAGE_DIR"])
            file_deleted, file_missing, delete_error = False, False, None

            try:
                # 关键修复2：将 _safe_resolve_under_storage 移出后，这里可以直接调用
                fp = _safe_resolve_under_storage(row.path, storage_root)
                if fp.exists():
                    try:
                        fp.unlink()
                        file_deleted = True
                    except Exception as e:
                        delete_error = f"failed to delete file: {e}"
                        app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
                else:
                    file_missing = True
            except RuntimeError as e:
                delete_error = str(e)
                app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

            try:
                with get_engine().begin() as conn:
                    conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
            except Exception as e:
                return jsonify({"error": f"database error during delete: {str(e)}"}), 503

            return jsonify({"deleted": True, "id": doc_id, "file_deleted": file_deleted, "file_missing": file_missing,
                            "note": delete_error}), 200


        @app.post("/api/create-watermark")
        @app.post("/api/create-watermark/<int:document_id>")
        @require_auth
        def create_watermark(document_id: int | None = None):
            if not document_id:
                document_id = (request.args.get("id") or request.args.get("documentid") or (request.is_json and (request.get_json(silent=True) or {}).get("id")))
            try:
                doc_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
            payload = request.get_json(silent=True) or {}
            method, intended_for, position, secret, key = payload.get("method"), payload.get("intended_for"), payload.get("position") or None, payload.get("secret"), payload.get("key")
            if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
                return jsonify({"error": "method, intended_for, secret, and key are required"}), 400
            try:
                with get_engine().connect() as conn:
                    row = conn.execute(
                        text("SELECT id, name, path FROM Documents WHERE id = :id AND ownerid = :uid"),
                        {"id": doc_id, "uid": int(g.user["id"])}
                    ).first()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            if not row:
                return jsonify({"error": "document not found"}), 404
            storage_root = Path(current_app.config["STORAGE_DIR"]).resolve()
            file_path = Path(row.path)
            if not file_path.is_absolute(): file_path = storage_root / file_path
            file_path = file_path.resolve()
            try:
                file_path.relative_to(storage_root)
            except ValueError:
                return jsonify({"error": "document path invalid"}), 500
            if not file_path.exists():
                return jsonify({"error": "file missing on disk"}), 410
            try:
                if not WMUtils.is_watermarking_applicable(method=method, pdf=str(file_path), position=position):
                    return jsonify({"error": "watermarking method not applicable"}), 400
            except Exception as e:
                return jsonify({"error": f"watermark applicability check failed: {e}"}), 400
            try:
                wm_bytes = WMUtils.apply_watermark(pdf=str(file_path), secret=secret, key=key, method=method, position=position)
                if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                    return jsonify({"error": "watermarking produced no output"}), 500
            except Exception as e:
                return jsonify({"error": f"watermarking failed: {e}"}), 500
            base_name = Path(row.name or file_path.name).stem
            intended_slug = secure_filename(intended_for)
            dest_dir = file_path.parent / "watermarks"
            dest_dir.mkdir(parents=True, exist_ok=True)
            candidate = f"{base_name}__{intended_slug}.pdf"
            dest_path = dest_dir / candidate
            try:
                with dest_path.open("wb") as f:
                    f.write(wm_bytes)
            except Exception as e:
                return jsonify({"error": f"failed to write watermarked file: {e}"}), 500
            link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()
            try:
                with get_engine().begin() as conn:
                    conn.execute(
                        text("INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path) VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)"),
                        {"documentid": doc_id, "link": link_token, "intended_for": intended_for, "secret": secret, "method": method, "position": position or "", "path": str(dest_path)}
                    )
                    vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
            except Exception as e:
                try: dest_path.unlink(missing_ok=True)
                except Exception: pass
                return jsonify({"error": f"database error during version insert: {e}"}), 503
            return jsonify({"id": vid, "documentid": doc_id, "link": link_token, "intended_for": intended_for, "method": method, "position": position, "filename": candidate, "size": len(wm_bytes)}), 201

        @app.post("/api/load-plugin")
        @require_auth
        def load_plugin():
            payload = request.get_json(silent=True) or {}
            filename = (payload.get("filename") or "").strip()
            if not filename:
                return jsonify({"error": "filename is required"}), 400
            storage_root = Path(current_app.config["STORAGE_DIR"])
            plugins_dir = storage_root / "files" / "plugins"
            try:
                plugins_dir.mkdir(parents=True, exist_ok=True)
                plugin_path = plugins_dir / filename
            except Exception as e:
                return jsonify({"error": f"plugin path error: {e}"}), 500
            if not plugin_path.exists():
                return jsonify({"error": f"plugin file not found at {plugin_path}"}), 404
            try:
                with plugin_path.open("rb") as f:
                    obj = _pickle.load(f)
            except Exception as e:
                return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400
            cls = obj if isinstance(obj, type) else obj.__class__
            method_name = cls.__dict__.get("name") or cls.__name__

            if not method_name or not isinstance(method_name, str):
                return jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}), 400

            if not issubclass(cls, WatermarkingMethod) or inspect.isabstract(cls):
                return jsonify({"error": "plugin must be a non-abstract subclass of WatermarkingMethod"}), 400


            # 既然已经确认是具体类，我们可以安全地实例化了
            WMUtils.METHODS[method_name] = cls()
            return jsonify({
                "loaded": True,
                "filename": filename,
                "registered_as": method_name,
                "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
                "methods_count": len(WMUtils.METHODS)
            }), 201

        @app.get("/api/get-watermarking-methods")
        def get_watermarking_methods():
            methods = [{"name": m, "description": WMUtils.get_method(m).get_usage()} for m in WMUtils.METHODS]
            return jsonify({"methods": methods, "count": len(methods)}), 200

        @app.post("/api/read-watermark")
        @app.post("/api/read-watermark/<int:document_id>")
        @require_auth
        def read_watermark(document_id: int | None = None):
            if not document_id:
                document_id = (request.args.get("id") or request.args.get("documentid") or (request.is_json and (request.get_json(silent=True) or {}).get("id")))
            try:
                doc_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
            payload = request.get_json(silent=True) or {}
            method, key, position = payload.get("method"), payload.get("key"), payload.get("position") or None
            if not method or not isinstance(key, str):
                return jsonify({"error": "method and key are required"}), 400
            try:
                with get_engine().connect() as conn:
                    row = conn.execute(
                        text("SELECT id, name, path FROM Documents WHERE id = :id AND ownerid = :uid"),
                        {"id": doc_id, "uid": int(g.user["id"])}
                    ).first()
            except Exception as e:
                return jsonify({"error": f"database error: {str(e)}"}), 503
            if not row:
                return jsonify({"error": "document not found"}), 404
            storage_root = Path(current_app.config["STORAGE_DIR"]).resolve()
            file_path = Path(row.path)
            if not file_path.is_absolute(): file_path = storage_root / file_path
            file_path = file_path.resolve()
            try:
                file_path.relative_to(storage_root)
            except ValueError:
                return jsonify({"error": "document path invalid"}), 500
            if not file_path.exists():
                return jsonify({"error": "file missing on disk"}), 410
            secret = None
            try:
                secret = WMUtils.read_watermark(method=method, pdf=str(file_path), key=key)
            except Exception as e:
                return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400
            return jsonify({"documentid": doc_id, "secret": secret, "method": method, "position": position}), 201

    # 在函数的最后返回 app
    return app


# --- WSGI 入口点（保持不变） ---
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)