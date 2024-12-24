from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, TextAreaField, DecimalField, FileField, SubmitField
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired, NumberRange, Length
from werkzeug.utils import secure_filename
import os
from flask_login import current_user, LoginManager, UserMixin
from datetime import datetime

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'de45e89a9c7b41c2a3f7d1e6ab9f423b'  # Secret key for session management
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Folder for image uploads
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB limit for uploaded files

# Enable CSRF protection globally
csrf = CSRFProtect(app)

# Initialize LoginManager for handling user sessions
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# User class to represent a user, inheriting from UserMixin for session handling
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Helper function to check if a file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Forms for product submission and messaging
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    price = DecimalField('Price', validators=[DataRequired(), NumberRange(min=0.01)])
    image = FileField('Product Image', validators=[DataRequired()])
    submit = SubmitField('Add Product')

class MessageForm(FlaskForm):
    recipient = StringField('Recipient', validators=[DataRequired()])
    message_body = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

# Function to get a database connection
def get_db_connection():
    try:
        conn = sqlite3.connect('users.db')
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

# Initialize the database and create tables if they do not exist
def init_db():
    conn = get_db_connection()
    if conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            full_name TEXT NOT NULL,
                            email TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS products (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            description TEXT NOT NULL,
                            price REAL NOT NULL,
                            added_by TEXT NOT NULL,
                            image_filename TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS messages (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            sender TEXT NOT NULL,
                            receiver TEXT NOT NULL,
                            message_body TEXT NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')
        conn.commit()
        conn.close()

# Function to load a user by ID, used by the LoginManager
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Routes
@app.route('/')
def home():
    return render_template('index.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    form = FlaskForm()
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate form inputs
        if not all([name, email, password, confirm_password]):
            flash("All fields are required.")
            return render_template('signup.html', name=name, email=email, form=form)

        if password != confirm_password:
            flash("Passwords do not match.")
            return render_template('signup.html', name=name, email=email, form=form)

        conn = get_db_connection()
        if conn:
            existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if existing_user:
                flash("Email already exists.")
                conn.close()
                return render_template('signup.html', name=name, email=email, form=form)

            # Hash the password before storing it
            hashed_password = generate_password_hash(password)
            conn.execute('INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
                         (name, email, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    form = FlaskForm()
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Validate form inputs
        if not (email and password):
            flash("All fields are required.")
            return render_template('login.html', email=email, form=form)

        conn = get_db_connection()
        if conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()

            # Check if the password matches
            if user and check_password_hash(user['password'], password):
                session['user'] = user['email']
                return redirect(url_for('dashboard'))

        flash("Invalid email or password.")
        return render_template('login.html', email=email, form=form)

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn:
        total_farms = conn.execute('SELECT COUNT(DISTINCT added_by) FROM products').fetchone()[0]
        total_orders = conn.execute('SELECT COUNT(*) FROM products WHERE added_by = ?', (session['user'],)).fetchone()[0]
        earnings = total_orders * 10  # Placeholder for earnings calculation
        user = conn.execute('SELECT full_name FROM users WHERE email = ?', (session['user'],)).fetchone()
        conn.close()

        return render_template(
            'dashboard.html',
            user=user['full_name'] if user else "User",
            total_farms=total_farms,
            total_orders=total_orders,
            earnings=earnings
        )

# Route to serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Route for the feed page to display products
@app.route('/feed')
def feed():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()

    return render_template('feed.html', products=products)

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'user' not in session:
        return redirect(url_for('login'))

    form = ProductForm()
    if form.validate_on_submit():
        file = form.image.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Convert price to float
            price = float(form.price.data)

            # Add the product to the database with the image filename
            conn = get_db_connection()
            if conn:
                conn.execute('''INSERT INTO products (name, description, price, added_by, image_filename)
                                VALUES (?, ?, ?, ?, ?)''',
                             (form.name.data, form.description.data, price, session['user'], filename))
                conn.commit()
                conn.close()

            flash('Product added successfully!', 'success')
            return redirect(url_for('feed'))
        flash('Invalid file type. Please upload an image.', 'danger')

    return render_template('add_product.html', form=form)

# Route to handle product purchase
@app.route('/buy/<int:product_id>', methods=['GET', 'POST'])
def buy_product(product_id):
    conn = get_db_connection()

    # Fetch the product details
    product = conn.execute('SELECT p.id, p.name, p.description, p.price, p.image_filename, p.added_by, u.full_name, u.email '
                            'FROM products p JOIN users u ON p.added_by = u.email WHERE p.id = ?',
                            (product_id,)).fetchone()

    if not product:
        conn.close()
        flash('Product not found', 'danger')
        return redirect(url_for('feed'))

    if request.method == 'POST':
        # Redirect to the uploader's email address
        uploader_email = product['email']
        conn.close()
        return redirect(f"mailto:{uploader_email}")

    conn.close()
    return render_template('buy.html', product=product, form=FlaskForm())

# Route to display user profile
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_data = conn.execute('SELECT full_name, email, created_at FROM users WHERE email = ?', (session['user'],)).fetchone()
    conn.close()

    return render_template('profile.html', user=user_data)

# Route to log out the user and end the session
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# Main entry point for running the application
if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)  # Run the Flask app in debug mode
