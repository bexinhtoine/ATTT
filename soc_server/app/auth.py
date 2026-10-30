# -*- coding: utf-8 -*-
"""
auth.py - Xác thực và phân quyền người dùng Web SOC.

* Đăng nhập bằng phiên (session cookie), mật khẩu băm (Werkzeug PBKDF2/scrypt).
* Khóa tạm thời tài khoản sau LOGIN_MAX_FAILURES lần sai trong LOGIN_LOCK_SECONDS giây.
* Ba vai trò: admin (toàn quyền), analyst (xử lý cảnh báo, sửa luật, KB), viewer (chỉ xem).
* Mọi thao tác quan trọng được ghi vào bảng audit_logs.
"""
import time
from functools import wraps

from flask import (Blueprint, render_template, request, redirect, url_for, session, g, flash,
                   current_app, abort, jsonify)

from .extensions import db
from .models import User, AuditLog, utcnow

bp = Blueprint("auth", __name__)
_failed_attempts = {}      # key (username, ip) -> {"count": n, "lock_until": ts}


def audit(action, target=None, detail=None, success=True, user=None):
    """Ghi nhật ký thao tác người dùng."""
    user = user if user is not None else getattr(g, "user", None)
    db.session.add(AuditLog(user_id=user.id if user else None, username=user.username if user else None,
                            action=action, target=str(target)[:128] if target else None,
                            detail=str(detail)[:2000] if detail else None,
                            ip=request.remote_addr if request else None, success=success))
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


def load_current_user():
    g.user = None
    uid = session.get("user_id")
    if uid:
        user = db.session.get(User, uid)
        if user and user.is_active:
            g.user = user
        else:
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Yêu cầu đăng nhập"}), 401
            return redirect(url_for("auth.login", next=request.full_path if request.query_string else request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.get("user") is None:
                return redirect(url_for("auth.login", next=request.path))
            if g.user.role not in roles:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Không đủ quyền"}), 403
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _lock_state(key):
    st = _failed_attempts.get(key)
    if st and st.get("lock_until", 0) > time.time():
        return int(st["lock_until"] - time.time())
    return 0


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.get("user"):
        return redirect(url_for("main.dashboard"))
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        key = (username.lower(), request.remote_addr)
        remaining = _lock_state(key)
        if remaining:
            error = "Tài khoản tạm khóa do đăng nhập sai nhiều lần. Thử lại sau %d giây." % remaining
            audit("login_locked", username, "Đăng nhập khi đang bị khóa", success=False)
        else:
            user = User.query.filter_by(username=username).first()
            if user and user.is_active and user.check_password(password):
                session.clear()
                session["user_id"] = user.id
                session.permanent = True
                user.last_login = utcnow()
                user.failed_logins = 0
                db.session.commit()
                _failed_attempts.pop(key, None)
                audit("login_success", username, "Đăng nhập thành công", user=user)
                nxt = request.args.get("next") or request.form.get("next")
                if nxt and nxt.startswith("/") and not nxt.startswith("//"):
                    return redirect(nxt)
                return redirect(url_for("main.dashboard"))
            if len(_failed_attempts) > 5000:        # dọn bộ nhớ: bỏ các mục đã hết hạn khóa
                for k in [k for k, v in _failed_attempts.items() if v.get("lock_until", 0) < time.time()]:
                    _failed_attempts.pop(k, None)
            st = _failed_attempts.setdefault(key, {"count": 0, "lock_until": 0})
            st["count"] += 1
            max_fail = current_app.config.get("LOGIN_MAX_FAILURES", 5)
            if st["count"] >= max_fail:
                st["lock_until"] = time.time() + current_app.config.get("LOGIN_LOCK_SECONDS", 300)
                st["count"] = 0
                error = "Sai thông tin đăng nhập quá %d lần. Tài khoản bị khóa tạm thời." % max_fail
            else:
                error = "Tên đăng nhập hoặc mật khẩu không đúng (lần %d/%d)." % (st["count"], max_fail)
            if user:
                user.failed_logins = (user.failed_logins or 0) + 1
                db.session.commit()
            audit("login_failed", username, "Sai mật khẩu hoặc tài khoản không tồn tại", success=False)
    return render_template("login.html", error=error, next=request.args.get("next", ""))


@bp.route("/logout")
def logout():
    if g.get("user"):
        audit("logout", g.user.username, "Đăng xuất")
    session.clear()
    flash("Bạn đã đăng xuất.", "info")
    return redirect(url_for("auth.login"))
