from flask import Flask, request, redirect, url_for, render_template, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User
from db import get_db_connection
from werkzeug.security import check_password_hash, generate_password_hash
import os
import uuid
from flask_wtf.csrf import CSRFProtect, CSRFError
from datetime import datetime, date



app = Flask(__name__)
secret_key = os.urandom(24)
app.secret_key = secret_key
csrf = CSRFProtect(app)


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

## OTHERS
#--- Format rupiah --- 
def format_rupiah(amount):
    return f"Rp{amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

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
            email = request.form.get('email', "-")
            phone_number = request.form.get('phone_number', "-")
            address = request.form.get('address', "-")
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

            email = request.form.get('email', "-")
            phone_number = request.form.get('phone_number', "-")
            address = request.form.get('address', "-")

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
            phone_number = request.form.get('phone_number', "-")
            address = request.form.get('address', "-")

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
            phone_number = request.form.get('phone_number', "-")
            address = request.form.get('address', "-")

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
            description = request.form.get('description',"-")

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
@app.route('/edit_category/<int:category_id>', methods=['POST', 'GET'])
def edit_category(category_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM categories WHERE category_id = %s", (category_id,))
    category_data = cursor.fetchone()

    if not category_data:
        conn.close()
        return jsonify(status="error", message="Category tidak ditemukan"), 404

    try:
        name = request.form['name']
        description = request.form.get('description', "-")

        cursor.execute("""
            UPDATE categories
            SET name=%s, description=%s
            WHERE category_id=%s
        """, (name, description, category_id))

        conn.commit()
        conn.close()

        return jsonify(status="success", message="Kategori berhasil diperbarui")
    except Exception as e:
        conn.close()
        return jsonify(status="error", message=f"Gagal memperbarui kategori: {str(e)}"), 500

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

    # Ambil produk dan kategori dengan JOIN
    cursor.execute("""
        SELECT p.*, c.name AS category_name
        FROM products p
        JOIN categories c ON p.category_id = c.category_id
    """)
    products = cursor.fetchall()

    cursor.execute("SELECT category_id, name FROM categories")
    categories = cursor.fetchall()

    conn.close()

    # filter format rupiah
    app.jinja_env.filters['rupiah'] = format_rupiah

    return render_template('products/product.html', products=products, categories=categories, user=current_user)

# --- Route: Tambah product ---
@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        try:
            product_id = request.form['product_id']
            category_id = request.form['category_id']
            name = request.form['name']
            qty = int(request.form['qty'])
            harga_sewa = float(request.form['harga_sewa'])
            description = request.form.get('description', '-')
            status = request.form.get('status', 'tersedia')

            cursor.execute("""
                INSERT INTO products (product_id, category_id, name, qty, harga_sewa, description, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (product_id, category_id, name, qty, harga_sewa, description, status))
            conn.commit()
            return jsonify(status="success", message="Produk berhasil ditambahkan")
        except Exception as e:
            return jsonify(status="error", message=f"Gagal menambahkan produk: {str(e)}"), 500
        finally:
            conn.close()

    # untuk GET request: ambil daftar kategori
    cursor.execute("SELECT category_id, name FROM categories")
    categories = cursor.fetchall()
    conn.close()

    return render_template('products/add_product.html', categories=categories, user=current_user)

#--- Route: Edit product --- 
@app.route('/edit_product/<int:id>', methods=['POST'])
def edit_product(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        product_id = request.form['product_id']
        category_id = request.form['category_id']
        name = request.form['name']
        qty = int(request.form['qty'])
        harga_sewa = float(request.form['harga_sewa'])
        description = request.form.get('description', '-')

        cursor.execute("""
            UPDATE products
            SET product_id=%s, category_id=%s, name=%s, qty=%s, harga_sewa=%s, description=%s
            WHERE id=%s
        """, (product_id, category_id, name, qty, harga_sewa, description, id))

        conn.commit()
        return jsonify(status="success", message="Produk berhasil diperbarui")
    except Exception as e:
        return jsonify(status="error", message=str(e)), 500
    finally:
        conn.close()
    
#--- Route: Hapus product --- 
@app.route('/delete_product/<int:id>', methods=['POST'])
#@login_required
def delete_product(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("DELETE FROM products WHERE id = %s", (id,))
        conn.commit()
        conn.close()
        return jsonify(status='success', message='Product deleted successfully')
    except Exception as e:
        conn.close()
        return jsonify(status='error', message=f'Failed to delete product: {str(e)}'), 500


## MODULE TRANSAKSI
#--- Route: Halaman transaksi --- 
@app.route('/sewa')
#@login_required
def sewa():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()

    cursor.execute("SELECT * FROM customers")
    customers = cursor.fetchall()

    conn.close()

    # Generate nomor nota otomatis
    no_nota = f"NOTA-{uuid.uuid4().hex[:8].upper()}"

    return render_template('transactions/transaction.html', 
                           products=products, customers=customers, user=current_user,
                            no_nota=no_nota,
                           today=date.today())

#--- Route: cari ketersediaan produk ---
@app.route('/search-products', methods=['POST'])
def search_products():
    data = request.get_json()
    search_term = data.get('search_term', '')
    tanggal_sewa = data.get('tanggal_sewa')
    tanggal_kembali = data.get('tanggal_kembali')
    
    if not tanggal_sewa or not tanggal_kembali:
        return jsonify({'error': 'Tanggal sewa dan kembali harus diisi'}), 400
    
    # Validasi tanggal
    try:
        sewa_date = datetime.strptime(tanggal_sewa, '%Y-%m-%d').date()
        kembali_date = datetime.strptime(tanggal_kembali, '%Y-%m-%d').date()
        
        if sewa_date >= kembali_date:
            return jsonify({'error': 'Tanggal kembali harus setelah tanggal sewa'}), 400
            
    except ValueError:
        return jsonify({'error': 'Format tanggal tidak valid'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT 
            p.product_id, 
            p.name, 
            p.harga_sewa, 
            p.qty,
            COALESCE(SUM(
                CASE 
                    WHEN t.status_pengembalian = 'belum' 
                    AND t.tanggal_sewa < %s 
                    AND t.tanggal_kembali > %s 
                    THEN td.qty 
                    ELSE 0 
                END
            ), 0) as qty_disewa
        FROM products p
        LEFT JOIN transaction_details td ON p.product_id = td.product_id
        LEFT JOIN transactions t ON td.transaction_id = t.transaction_id
        WHERE (p.name LIKE %s OR p.product_id LIKE %s)
        GROUP BY p.product_id, p.name, p.harga_sewa, p.qty
        HAVING (p.qty - qty_disewa) > 0
        ORDER BY p.name
    """

    search_pattern = f'%{search_term}%'
    cursor.execute(query, (tanggal_kembali, tanggal_sewa, search_pattern, search_pattern))

    products = cursor.fetchall()

    # Hitung stok tersedia
    for product in products:
        product['stok_tersedia'] = product['qty'] - product['qty_disewa']

    cursor.close()
    conn.close()

    
    return jsonify(products)

#--- Route: Simpan transaksi ---
@app.route('/save_transaction', methods=['POST'])
def save_transaction():
    data = request.get_json()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Generate nota number
        today = datetime.now().strftime("%Y%m%d")
        cursor.execute("SELECT COUNT(*) FROM transactions WHERE DATE(tanggal_nota) = CURDATE()")
        daily_count = cursor.fetchone()[0] + 1
        no_nota = f"RNT{today}{daily_count:03d}"
        
        # Insert transaction
        transaction_query = """
            INSERT INTO transactions 
            (user_id, customer_id, no_nota, tanggal_nota, tanggal_sewa, tanggal_kembali, 
             status_pembayaran, status_pengembalian, total)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        cursor.execute(transaction_query, (
            1,  # Default user_id
            1,  # Default customer_id
            no_nota,
            datetime.now().date(),
            data['tanggal_sewa'],
            data['tanggal_kembali'],
            data['status_pembayaran'],
            'belum',
            data['total']
        ))
        
        transaction_id = cursor.lastrowid
        
        # Insert transaction details
        detail_query = """
            INSERT INTO transaction_details (transaction_id, product_id, qty, harga_sewa)
            VALUES (%s, %s, %s, %s)
        """
        
        for item in data['items']:
            cursor.execute(detail_query, (
                transaction_id,
                item['product_id'],
                item['qty'],
                item['harga_sewa']
            ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': 'Transaksi berhasil disimpan',
            'no_nota': no_nota
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)