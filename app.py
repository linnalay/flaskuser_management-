from flask import Flask, render_template, request, url_for, session, flash, redirect
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
import re
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Secure key for session management
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'expert_system'

mysql = MySQL(app)

# Helper function to check if user is logged in
def is_logged_in():
    return 'loggedin' in session

# Helper function to get user by email
def get_user_by_email(email):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
    return cursor.fetchone()

# Helper function to get user by ID
def get_user_by_id(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM user WHERE userid = %s', (user_id,))
    return cursor.fetchone()

# Index Route
@app.route('/')
def index():
    if is_logged_in():
        user_details = {
            'name': session.get('name', 'Guest'),
            'role': session.get('role', 'User'),
            'email': session.get('email', ''),
            'userid': session.get('userid'),
        }
        return render_template('index.html', user=user_details)
    return redirect(url_for('login'))

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user_by_email(email)

        if user and bcrypt.check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['userid'] = user['userid']
            session['name'] = user['name']
            session['role'] = user['role']
            session['email'] = user['email']
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password!')

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        country = request.form['country']

        if get_user_by_email(email):
            flash('User already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not name or not password or not email:
            flash('Please fill out all fields!')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor = mysql.connection.cursor()
            cursor.execute(
                'INSERT INTO user (name, email, password, role, country) VALUES (%s, %s, %s, %s, %s)',
                (name, email, hashed_password, role, country)
            )
            mysql.connection.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))

    return render_template('register.html')

# Users Route
@app.route('/users')
def users():
    if is_logged_in():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user')
        users = cursor.fetchall()
        return render_template('users.html', users=users)

    flash('You must log in to access this page.')
    return redirect(url_for('login'))

# Edit User Route
@app.route('/edit/<int:userid>', methods=['GET', 'POST'])
def edit(userid):
    if is_logged_in() and session['userid'] == userid:
        user = get_user_by_id(userid)
        if request.method == 'POST':
            name = request.form['name']
            role = request.form['role']
            country = request.form['country']

            if not re.match(r'[A-Za-z0-9 ]+', name):
                flash('Name must contain only letters, numbers, and spaces!')
            else:
                cursor = mysql.connection.cursor()
                cursor.execute(
                    'UPDATE user SET name=%s, role=%s, country=%s WHERE userid=%s',
                    (name, role, country, userid)
                )
                mysql.connection.commit()
                flash('User details updated successfully!')
                return redirect(url_for('index'))
        return render_template('edit.html', editUser=user)
    flash('Unauthorized access.')
    return redirect(url_for('index'))

# Change Password Route
@app.route('/password_change/<int:userid>', methods=['GET', 'POST'])
def password_change(userid):
    if is_logged_in() and session['userid'] == userid:
        if request.method == 'POST':
            password = request.form['password']
            confirm_password = request.form['confirm_pass']

            if password != confirm_password:
                flash('Passwords do not match!')
            else:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor = mysql.connection.cursor()
                cursor.execute(
                    'UPDATE user SET password=%s WHERE userid=%s',
                    (hashed_password, userid)
                )
                mysql.connection.commit()
                flash('Password updated successfully!')
                return redirect(url_for('index'))
        return render_template('password_change.html', changePassUserId=userid)

    flash('Unauthorized access.')
    return redirect(url_for('login'))

# View User Route
@app.route('/view/<int:userid>', methods=['GET'])
def view(userid):
    if is_logged_in():
        user = get_user_by_id(userid)
        if user:
            return render_template('view.html', user=user)
        flash('User not found.')
        return redirect(url_for('index'))
    flash('You must log in to view user details.')
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
