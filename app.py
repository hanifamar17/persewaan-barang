from flask import Flask, request, redirect, url_for, render_template, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User
from db import get_db_connection
from werkzeug.security import check_password_hash, generate_password_hash
import os

app = Flask(__name__)
secret_key = os.urandom(24)
app.secret_key = secret_key


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# --- Load user by ID for session ---
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return User(user_data['user_id'], user_data['username'], user_data['password'], user_data['role'])
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    return redirect(url_for('login'))

# --- Route: Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data and check_password_hash(user_data['password'], password_input):
            user = User(user_data['user_id'], user_data['username'], user_data['password'], user_data['role'])
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

# --- Route: Logout ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Route: Dashboard (akses berdasarkan role) ---
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', user=current_user)

## MODULE ADMI
#--- Route: Halaman user --- 
@app.route('/user')
@login_required
def user():
    if current_user.role not in ['superadmin', 'admin']:
        return "Access denied", 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template('admin/user.html', users=users)

# --- Route: Tambah User Baru (Hanya untuk admin) ---
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role not in ['superadmin', 'admin']:
        return "Access denied", 403

    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        email = request.form.get('email') or None
        phone_number = request.form.get('phone_number') or None
        address = request.form.get('address') or None
        role = request.form['role']  # admin or customer service

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (name, username, password, email, phone_number, address, role)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (name, username, password, email, phone_number, address, role))
        conn.commit()
        conn.close()
        flash('User added successfully', 'success')
        return redirect(url_for('add_user'))

    return render_template('admin/add_user.html')

#--- Route: Hapus user --- 
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in ['superadmin', 'admin']:
        return "Access denied", 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Cek apakah user yang akan dihapus adalah superadmin
    cursor.execute("SELECT role FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('User not found', 'danger')
    elif user['role'] == 'superadmin':
        flash('Cannot delete superadmin', 'warning')
    else:
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()
        flash('User deleted successfully', 'success')

    conn.close()
    return redirect(url_for('user'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['superadmin', 'admin']:
        return "Access denied", 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Ambil data user yang akan diedit
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user_data = cursor.fetchone()

    if not user_data:
        flash('User not found', 'danger')
        conn.close()
        return redirect(url_for('user'))

    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form.get('email') or None
        phone_number = request.form.get('phone_number') or None
        address = request.form.get('address') or None

        # Role hanya boleh diedit jika user yang diedit bukan superadmin
        if user_data['role'] != 'superadmin':
            role = request.form['role']
        else:
            role = user_data['role']  # tetap gunakan role lama

        cursor.execute("""
            UPDATE users
            SET name=%s, username=%s, email=%s, phone_number=%s, address=%s, role=%s
            WHERE user_id=%s
        """, (name, username, email, phone_number, address, role, user_id))
        conn.commit()
        conn.close()

        flash('User updated successfully', 'success')
        return redirect(url_for('user'))

    conn.close()
    return render_template('admin/edit_user.html', user=user_data)





if __name__ == '__main__':
    app.run(debug=True)