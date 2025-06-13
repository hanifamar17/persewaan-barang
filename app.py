from flask import Flask, request, redirect, url_for, render_template, flash, jsonify
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
#@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Route: Dashboard (akses berdasarkan role) ---
@app.route('/dashboard')
#@login_required
def dashboard():
    return render_template('index.html', user=current_user)

## MODULE MANAJEMEN USER
#--- Route: Halaman user --- 
@app.route('/user')
#@login_required
def user():
    if current_user.role not in ['superadmin', 'admin']:
        return "Access denied", 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template('admin/user.html', users=users, user=current_user)

# --- Route: Tambah User Baru (Hanya untuk admin) ---
@app.route('/add_user', methods=['GET', 'POST'])
#@login_required
def add_user():
    if current_user.role not in ['superadmin', 'admin']:
        return "Access denied", 403

    if request.method == 'POST':
        try:
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

            return jsonify(status="success", message="User berhasil ditambahkan")
        except Exception as e:
            return jsonify(status="error", message=f"Gagal menambahkan user: {str(e)}"), 500

    return render_template('admin/add_user.html', user=current_user)

#--- Route: Hapus user --- 
@app.route('/delete_user/<int:user_id>', methods=['POST'])
#@login_required
def delete_user(user_id):
    if current_user.role not in ['superadmin', 'admin']:
        return jsonify(status='error', message='Access denied'), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Cek apakah user yang akan dihapus adalah superadmin
    cursor.execute("SELECT role FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify(status='error', message='User not found'), 404

    if user['role'] == 'superadmin':
        conn.close()
        return jsonify(status='error', message='Cannot delete superadmin'), 403

    try:
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()
        conn.close()
        return jsonify(status='success', message='User deleted successfully')
    except Exception as e:
        conn.close()
        return jsonify(status='error', message=f'Failed to delete user: {str(e)}'), 500


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
#@login_required
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
        try:
            name = request.form['name']
            username = request.form['username']
            new_password = request.form.get('password')  # bisa kosong

            email = request.form.get('email') or None
            phone_number = request.form.get('phone_number') or None
            address = request.form.get('address') or None

            # Ambil data user lama dulu untuk password dan role
            cursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
            user_data = cursor.fetchone()
            if not user_data:
                return jsonify(status="error", message="User tidak ditemukan"), 404

            # Role hanya boleh diedit jika user yang diedit bukan superadmin
            if user_data['role'] != 'superadmin':
                role = request.form['role']
            else:
                role = user_data['role']  # tetap gunakan role lama

            if new_password and new_password.strip() != "":
                # Jika user isi password baru, hash dan update
                password_hashed = generate_password_hash(new_password)
            else:
                # Jika kosong, gunakan password lama dari DB
                password_hashed = user_data['password']

            cursor.execute("""
                UPDATE users
                SET name=%s, username=%s, password=%s, email=%s, phone_number=%s, address=%s, role=%s
                WHERE user_id=%s
            """, (name, username, password_hashed, email, phone_number, address, role, user_id))

            conn.commit()
            conn.close()

            return jsonify(status="success", message="User berhasil diperbarui")
        except Exception as e:
            return jsonify(status="error", message=f"Gagal memperbarui user: {str(e)}"), 500


    conn.close()
    return render_template('admin/edit_user.html', user=user_data)

#--- Route: Halaman Pelanggan --- 
@app.route('/customers')
#@login_required
def customers():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM customers")
    customers = cursor.fetchall()
    conn.close()

    return render_template('customers/customer.html', users=customers, user=current_user)

# --- Route: Tambah Pelanggan Baru ---
@app.route('/add_customer', methods=['GET', 'POST'])
#@login_required
def add_customer():
    if request.method == 'POST':
        try:
            name = request.form['name']
            phone_number = request.form.get('phone_number') or None
            address = request.form.get('address') or None

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO customers (name, phone_number, address)
                VALUES (%s, %s, %s)
            """, (name, phone_number, address))
            conn.commit()
            conn.close()

            return jsonify(status="success", message="Pelanggan berhasil ditambahkan")
        except Exception as e:
            return jsonify(status="error", message=f"Gagal menambahkan pelanggan: {str(e)}"), 500

    return render_template('customers/add_customer.html', user=current_user)

#--- Route: Hapus pelanggan --- 
@app.route('/delete_customer/<int:customer_id>', methods=['POST'])
#@login_required
def delete_customer(customer_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("DELETE FROM customers WHERE customer_id = %s", (customer_id,))
        conn.commit()
        conn.close()
        return jsonify(status='success', message='Customer deleted successfully')
    except Exception as e:
        conn.close()
        return jsonify(status='error', message=f'Failed to delete customer: {str(e)}'), 500
    
#--- Route: Edit pelanggan --- 
@app.route('/edit_customer/<int:customer_id>', methods=['GET', 'POST'])
#@login_required
def edit_customer(customer_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Ambil data user yang akan diedit
    cursor.execute("SELECT * FROM customers WHERE customer_id = %s", (customer_id,))
    customer_data = cursor.fetchone()

    if not customer_data:
        flash('Customer not found', 'danger')
        conn.close()
        return redirect(url_for('customers'))

    if request.method == 'POST':
        try:
            name = request.form['name']
            phone_number = request.form.get('phone_number') or None
            address = request.form.get('address') or None

            # Ambil data user lama dulu untuk password dan role
            cursor.execute("SELECT * FROM customers WHERE customer_id=%s", (customer_id,))
            customer_data = cursor.fetchone()
            if not customer_data:
                return jsonify(status="error", message="Pelanggan tidak ditemukan"), 404

            cursor.execute("""
                UPDATE customers
                SET name=%s, phone_number=%s, address=%s
                WHERE customer_id=%s
            """, (name, phone_number, address, customer_id))

            conn.commit()
            conn.close()

            return jsonify(status="success", message="Pelanggan berhasil diperbarui")
        except Exception as e:
            return jsonify(status="error", message=f"Gagal memperbarui pelanggan: {str(e)}"), 500


    conn.close()
    return render_template('customers/edit_customer.html', user=customer_data)


## MODULE MANAJEMEN PRODUK
#--- Route: Halaman Kategori --- 
@app.route('/categories')
#@login_required
def categories():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()

    conn.close()

    return render_template('products/category.html', categories=categories, user=current_user)

# --- Route: Tambah category ---
@app.route('/add_category', methods=['GET', 'POST'])
#@login_required
def add_category():
    if request.method == 'POST':
        try:
            name = request.form['name']
            description = request.form.get('description') or None

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO categories (name, description)
                VALUES (%s, %s)
            """, (name, description))
            conn.commit()
            conn.close()

            return jsonify(status="success", message="Kategori berhasil ditambahkan")
        except Exception as e:
            return jsonify(status="error", message=f"Gagal menambahkan kategori: {str(e)}"), 500

    return render_template('products/add_category.html', user=current_user)

#--- Route: Edit category --- 
@app.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
#@login_required
def edit_category(category_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Ambil data category yang akan diedit
    cursor.execute("SELECT * FROM categories WHERE category_id = %s", (category_id,))
    category_data = cursor.fetchone()

    if not category_data:
        flash('Category not found', 'danger')
        conn.close()
        return redirect(url_for('categories'))

    if request.method == 'POST':
        try:
            name = request.form['name']
            description = request.form.get('description') or None

            # Ambil data category lama
            cursor.execute("SELECT * FROM categories WHERE category_id=%s", (category_id,))
            category_data = cursor.fetchone()
            if not category_data:
                return jsonify(status="error", message="Category tidak ditemukan"), 404

            cursor.execute("""
                UPDATE categories
                SET name=%s, description=%s
                WHERE category_id=%s
            """, (name, description, category_id))

            conn.commit()
            conn.close()

            return jsonify(status="success", message="Kategori berhasil diperbarui")
        except Exception as e:
            return jsonify(status="error", message=f"Gagal memperbarui kategori: {str(e)}"), 500


    conn.close()
    return render_template('products/edit_category.html', category=category_data, user=current_user)

#--- Route: Hapus category --- 
@app.route('/delete_category/<int:category_id>', methods=['POST'])
#@login_required
def delete_category(category_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("DELETE FROM categories WHERE category_id = %s", (category_id,))
        conn.commit()
        conn.close()
        return jsonify(status='success', message='Category deleted successfully')
    except Exception as e:
        conn.close()
        return jsonify(status='error', message=f'Failed to delete category: {str(e)}'), 500
    
#--- Route: Halaman produk --- 
@app.route('/products')
#@login_required
def products():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()

    conn.close()

    return render_template('products/product.html', products=products, user=current_user)

if __name__ == '__main__':
    app.run(debug=True)