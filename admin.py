# admin.py (FILE MỚI)

import os
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

# --- Cấu hình Blueprint ---
admin_blueprint = Blueprint('admin_blueprint', __name__,
                            template_folder='templates',
                            static_folder='static')

# --- Thiết lập User Model Đơn giản (Không cần Database) ---
# Trong thực tế, bạn sẽ lấy user từ CSDL. Ở đây, chúng ta hardcode để demo.
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# TẠO TÀI KHOẢN ADMIN CỦA BẠN Ở ĐÂY
# Thay "admin" và "your_super_secret_password" bằng thông tin của bạn
users = {
    "1": User(id="1", username="admin", password="admin"),
    "2": User(id="2", username="DuongPham", password="NKer")
}
user_by_username = {user.username: user for user in users.values()}

# --- Cấu hình Flask-Login ---
# LoginManager sẽ được khởi tạo trong app.py
login_manager = LoginManager()
login_manager.login_view = "admin_blueprint.login" # Route để redirect khi chưa đăng nhập

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
    # Đây là trang chính của dashboard
    return render_template("admin_dashboard.html")

# --- Các API cho Dashboard (Để JavaScript gọi) ---

@admin_blueprint.route("/api/logs")
@login_required
def get_logs():
    """Đọc 50 dòng log cuối cùng và trả về dạng JSON."""
    LOG_FILE = "cybershield.log" # Tên file log sẽ được cấu hình trong app.py
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            last_50_lines = lines[-50:]
            return jsonify({"logs": last_50_lines})
    except FileNotFoundError:
        return jsonify({"logs": ["Log file not found yet."]})
    except Exception as e:
        return jsonify({"logs": [f"Error reading log file: {str(e)}"]}), 500

# Các hàm điều khiển khác (chưa triển khai, để bạn phát triển sau)
@admin_blueprint.route("/api/test_analyzer", methods=["POST"])
@login_required
def test_analyzer():
    # TODO: Lấy text từ request, gọi hàm analyze và trả về kết quả
    return jsonify({"status": "Not implemented yet"})

@admin_blueprint.route("/api/leo/add", methods=["POST"])
@login_required
def add_to_leo():
    # TODO: Lấy dữ liệu từ form, gọi API của Google Apps Script

    return jsonify({"status": "Added successfully (Not implemented yet)"})
