# admin.py (ĐÃ SỬA LỖI SYNTAX)

import os
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

# --- Cấu hình Blueprint ---
admin_blueprint = Blueprint('admin_blueprint', __name__,
                            template_folder='templates',
                            static_folder='static')

# --- Thiết lập User Model ---
# Class này định nghĩa cấu trúc của một User
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# <<< SỬA LẠI: ĐƯA KHỐI NÀY RA NGOÀI, NGANG HÀNG VỚI CLASS >>>
# Đọc thông tin đăng nhập từ biến môi trường để đảm bảo an toàn
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

if not ADMIN_PASSWORD:
    # Dừng server nếu mật khẩu admin chưa được cài đặt
    raise ValueError("Biến môi trường ADMIN_PASSWORD chưa được thiết lập trên Render!")

# Tạo user duy nhất từ các biến môi trường
users = {
    "1": User(id="1", username=ADMIN_USERNAME, password=ADMIN_PASSWORD)
}
user_by_username = {user.username: user for user in users.values()}
# <<< KẾT THÚC PHẦN SỬA LỖI >>>


# --- Cấu hình Flask-Login ---
login_manager = LoginManager()
login_manager.login_view = "admin_blueprint.login"

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# --- Các Route cho Trang Admin ---

@admin_blueprint.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = user_by_username.get(username)
        # So sánh password an toàn
        if user and user.password == password:
            login_user(user)
            return redirect(url_for("admin_blueprint.dashboard"))
        else:
            flash("Tên đăng nhập hoặc mật khẩu không đúng.", "error")
    return render_template("admin_login.html")

@admin_blueprint.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("admin_blueprint.login"))

@admin_blueprint.route("/dashboard")
@login_required
def dashboard():
    return render_template("admin_dashboard.html")

# --- Các API cho Dashboard ---

@admin_blueprint.route("/api/logs")
@login_required
def get_logs():
    LOG_FILE = "cybershield.log"
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            last_50_lines = lines[-50:]
            # Đảo ngược lại để dòng mới nhất ở trên cùng
            return jsonify({"logs": last_50_lines[::-1]})
    except FileNotFoundError:
        return jsonify({"logs": ["Log file not found yet."]})
    except Exception as e:
        return jsonify({"logs": [f"Error reading log file: {str(e)}"]}), 500
