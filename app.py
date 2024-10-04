from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import logging

# Configure logging
logging.basicConfig(filename='error.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Use a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Load user callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home route
@app.route('/')
def home():
    return redirect(url_for('register'))

# Registration route
# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        # Check if the email already exists
        existing_email_user = User.query.filter_by(email=email).first()
        if existing_email_user:
            flash('Email is already in use. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Check if the username already exists
        existing_username_user = User.query.filter_by(username=username).first()
        if existing_username_user:
            flash('Username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Create and store the user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')



# Login route
# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')  # This will be either username or email
        password = request.form.get('password')

        # Check if the identifier is an email or a username
        user = None
        if identifier and '@' in identifier:  # If it contains '@', treat it as an email
            user = User.query.filter_by(email=identifier).first()
        elif identifier:  # Otherwise, treat it as a username
            user = User.query.filter_by(username=identifier).first()

        # Validate user and password
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')  # Show user-specific welcome message
            return redirect(url_for('dashboard'))
        else:
            flash(f'Login Unsuccessful for {identifier}. Please check your credentials.', 'danger')  # Include identifier in the message

    return render_template('login.html')


# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')  # Create a template for the dashboard

# Settings route
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')  # Create a template for settings

# Main menu route
@app.route('/main-menu')
@login_required
def main_menu():
    return render_template('main_menu.html')  # Create a template for the main menu

# Look for professors route
@app.route('/look-for-professors')
@login_required
def look_for_professors():
    return render_template('look_for_professors.html')  # Create a template for looking for professors

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the database tables if they do not exist
    app.run(debug=True)
