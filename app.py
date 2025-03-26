from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///kubecertify.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    kubeconfigs = db.relationship('KubeConfig', backref='user', lazy=True)
    alerts = db.relationship('Alert', backref='user', lazy=True)

class KubeConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    days = db.Column(db.Integer, default=0)
    hours = db.Column(db.Integer, default=0)
    minutes = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    add_to_calendar = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def total_minutes(self):
        return (self.days * 24 * 60) + (self.hours * 60) + self.minutes

    @property
    def expiration_date(self):
        return datetime.utcnow() + timedelta(minutes=self.total_minutes)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
            
        user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
            
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/kubeconfig', methods=['GET', 'POST'])
@login_required
def kubeconfig():
    if request.method == 'POST':
        if 'kubeconfig' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('kubeconfig'))
            
        file = request.files['kubeconfig']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('kubeconfig'))
            
        content = file.read().decode('utf-8')
        name = request.form.get('name', file.filename)
        
        kubeconfig = KubeConfig(
            name=name,
            content=content,
            user_id=current_user.id
        )
        db.session.add(kubeconfig)
        db.session.commit()
        
        flash('Kubeconfig uploaded successfully', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('kubeconfig.html')

@app.route('/secrets')
@login_required
def secrets():
    return render_template('secrets.html')

@app.route('/alerts', methods=['GET', 'POST'])
@login_required
def alerts():
    if request.method == 'POST':
        days = int(request.form.get('days', 0))
        hours = int(request.form.get('hours', 0))
        minutes = int(request.form.get('minutes', 0))
        add_to_calendar = request.form.get('calendar') == 'on'
        
        alert = Alert(
            user_id=current_user.id,
            days=days,
            hours=hours,
            minutes=minutes,
            add_to_calendar=add_to_calendar
        )
        db.session.add(alert)
        db.session.commit()
        
        if add_to_calendar:
            # Here you would implement calendar integration
            # For example, using Google Calendar API
            pass
            
        flash('Alert settings updated', 'success')
        return redirect(url_for('dashboard'))
    return render_template('alerts.html')

@app.route('/renewal')
@login_required
def renewal():
    return render_template('renewal.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 