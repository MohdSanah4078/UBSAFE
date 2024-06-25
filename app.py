from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Ensure tables are created
@app.before_request
def create_tables():
    if not os.path.exists('passwords.db'):
        db.create_all()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You have successfully signed up!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Incorrect username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()  # or use session.pop('user_id', None) if you are storing user_id in session
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


@app.route('/home')
def home():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    user_id = session['user_id']
    passwords = Password.query.filter_by(user_id=user_id).all()
    return render_template('home.html', passwords=passwords)

@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_id = session['user_id']
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        new_password = Password(user_id=user_id, website=website, username=username, password=password)
        db.session.add(new_password)
        db.session.commit()
        flash('Password added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('add_password.html')

@app.route('/edit_password/<int:id>', methods=['GET', 'POST'])
def edit_password(id):
    if 'user_id' not in session:
        flash('Please log in to edit a password.', 'warning')
        return redirect(url_for('login'))
    password = Password.query.get_or_404(id)
    if request.method == 'POST':
        password.website = request.form['website']
        password.username = request.form['username']
        password.password = request.form['password']
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('edit_password.html', password=password)

@app.route('/delete_password/<int:id>', methods=['POST'])
def delete_password(id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    password_entry = Password.query.get_or_404(id)
    db.session.delete(password_entry)
    db.session.commit()
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
