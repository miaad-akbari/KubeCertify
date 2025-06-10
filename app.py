from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import tempfile
import base64
from kubernetes import client, config
from kubernetes.config import ConfigException
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.backends import default_backend

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///kubecertify.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Kubernetes client
k8s_client = None

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
    secret_name = db.Column(db.String(255), nullable=False)
    days_before = db.Column(db.Integer, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def days_until_expiry(self):
        return (self.expiration_date - datetime.utcnow()).days

    @property
    def status(self):
        if self.days_until_expiry <= 30:
            return 'danger'
        elif self.days_until_expiry <= 60:
            return 'warning'
        return 'success'

class CertificateRenewal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    secret_name = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    validity_days = db.Column(db.Integer, nullable=False)
    renewed_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

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
    try:
        if not k8s_client:
            flash('Please upload a valid kubeconfig first', 'error')
            return redirect(url_for('kubeconfig'))
            
        # Get cluster statistics
        namespaces = k8s_client.list_namespace()
        total_namespaces = len(namespaces.items)
        
        # Get TLS secrets statistics
        tls_secrets = []
        expiring_soon = []
        
        # Use a single API call to get all secrets across namespaces (TLS)
        all_secrets = k8s_client.list_secret_for_all_namespaces()
        for secret in all_secrets.items:
            if secret.type == 'kubernetes.io/tls':
                tls_secrets.append(secret)
                if secret.data and 'tls.crt' in secret.data:
                    try:
                        cert_pem = base64.b64decode(secret.data['tls.crt']).decode('utf-8')
                        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                        expiration_date = cert.not_valid_after_utc
                        days_until_expiry = (expiration_date - datetime.now()).days
                        
                        if days_until_expiry <= 90:  # Show certificates expiring in 90 days or less
                            expiring_soon.append({
                                'name': secret.metadata.name,
                                'namespace': secret.metadata.namespace,
                                'days_until_expiry': days_until_expiry,
                                'expiration_date': expiration_date
                            })
                    except Exception as e:
                        print(f"Error parsing certificate for {secret.metadata.name}: {str(e)}")
        
        return render_template('dashboard.html', 
                             total_namespaces=total_namespaces,
                             total_tls_secrets=len(tls_secrets),
                             expiring_soon=expiring_soon)
        
    except Exception as e:
        flash(f'Error fetching dashboard data: {str(e)}', 'error')
        return redirect(url_for('index'))

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
            
        try:
            content = file.read().decode('utf-8')
            name = request.form.get('name', file.filename)
            
            # Save kubeconfig to a temporary file
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name
            
            try:
                # Load kubeconfig
                config.load_kube_config(temp_file_path)
                
                # Initialize Kubernetes client
                global k8s_client
                k8s_client = client.CoreV1Api()
                
                # Test the connection by getting cluster info
                try:
                    cluster_info = k8s_client.list_namespace()
                    namespaces = [ns.metadata.name for ns in cluster_info.items]
                    
                    # Save kubeconfig to database
                    kubeconfig = KubeConfig(
                        name=name,
                        content=content,
                        user_id=current_user.id
                    )
                    db.session.add(kubeconfig)
                    db.session.commit()
                    
                    flash(f'Kubeconfig uploaded successfully. Found {len(namespaces)} namespaces.', 'success')
                    return redirect(url_for('dashboard'))
                    
                except Exception as e:
                    flash(f'Error connecting to cluster: {str(e)}', 'error')
                    return redirect(url_for('kubeconfig'))
                    
            except ConfigException as e:
                flash(f'Error loading kubeconfig: {str(e)}', 'error')
                return redirect(url_for('kubeconfig'))
                
            finally:
                # Clean up temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
                    
        except Exception as e:
            flash(f'Error processing kubeconfig file: {str(e)}', 'error')
            return redirect(url_for('kubeconfig'))
        
    return render_template('kubeconfig.html')

@app.route('/secrets', methods=['GET', 'POST'])
@login_required
def secrets():
    if not k8s_client:
        flash('Please upload a kubeconfig file first', 'error')
        return redirect(url_for('kubeconfig'))
        
    try:
        # Get all secrets across all namespaces
        secrets_list = []
        namespaces = k8s_client.list_namespace()
        
        for ns in namespaces.items:
            try:
                secrets = k8s_client.list_namespaced_secret(ns.metadata.name)
                for secret in secrets.items:
                    if secret.type == 'kubernetes.io/tls':
                        try:
                            # Decode TLS certificate data
                            tls_cert = secret.data.get('tls.crt')
                            if tls_cert:
                                cert = x509.load_pem_x509_certificate(base64.b64decode(tls_cert))
                                expiration_date = cert.not_valid_after_utc
                                start_date = cert.not_valid_before_utc
                                days_remaining = (expiration_date - datetime.utcnow()).days
                                
                                secrets_list.append({
                                    'name': secret.metadata.name,
                                    'namespace': secret.metadata.namespace,
                                    'type': secret.type,
                                    'start_date': start_date,
                                    'expiration_date': expiration_date,
                                    'days_remaining': days_remaining
                                })
                        except Exception as e:
                            print(f"Error processing secret {secret.metadata.name}: {str(e)}")
                            # Add the secret even if we can't parse the certificate
                            secrets_list.append({
                                'name': secret.metadata.name,
                                'namespace': secret.metadata.namespace,
                                'type': secret.type,
                                'start_date': None,
                                'expiration_date': None,
                                'days_remaining': None
                            })
            except Exception as e:
                print(f"Error listing secrets in namespace {ns.metadata.name}: {str(e)}")
                continue
        
        if request.method == 'POST':
            action = request.form.get('action')
            selected_secrets = request.form.getlist('selected_secrets')
            
            if action == 'set_alerts':
                return redirect(url_for('alerts', selected_secrets=','.join(selected_secrets)))
            elif action == 'renew':
                # Handle renewal logic here
                flash(f'Renewal process started for {len(selected_secrets)} secrets', 'success')
                return redirect(url_for('secrets'))
        
        return render_template('secrets.html', secrets=secrets_list)
        
    except Exception as e:
        flash(f'Error fetching secrets: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/alerts', methods=['GET', 'POST'])
@login_required
def alerts():
    if request.method == 'POST':
        secret_name = request.form.get('secret_name')
        days_before = int(request.form.get('days_before'))
        notification_type = request.form.get('notification_type')
        email = request.form.get('email')
        
        # Create new alert
        alert = Alert(
            secret_name=secret_name,
            days_before=days_before,
            notification_type=notification_type,
            email=email,
            user_id=current_user.id
        )
        
        db.session.add(alert)
        db.session.commit()
        
        # If calendar event is requested, create it
        if notification_type in ['calendar', 'both']:
            try:
                # Get secret details
                namespace, name = secret_name.split('/')
                secret = k8s_client.read_namespaced_secret(name, namespace)
                tls_cert = secret.data.get('tls.crt')
                if tls_cert:
                    cert = x509.load_pem_x509_certificate(base64.b64decode(tls_cert))
                    expiration_date = cert.not_valid_after_utc
                    
                    # Create calendar event
                    # Note: You'll need to implement calendar integration
                    # This is a placeholder for the actual implementation
                    pass
            except Exception as e:
                flash(f'Error creating calendar event: {str(e)}', 'warning')
        
        flash('Alert set successfully', 'success')
        return redirect(url_for('alerts'))
    
    # Get selected secrets from query parameter
    selected_secrets = request.args.get('selected_secrets', '').split(',')
    
    # Get all secrets for the dropdown
    secrets_list = []
    if k8s_client:
        try:
            namespaces = k8s_client.list_namespace()
            for ns in namespaces.items:
                secrets = k8s_client.list_namespaced_secret(ns.metadata.name)
                for secret in secrets.items:
                    if secret.type == 'kubernetes.io/tls':
                        secrets_list.append({
                            'name': secret.metadata.name,
                            'namespace': secret.metadata.namespace
                        })
        except Exception as e:
            flash(f'Error fetching secrets: {str(e)}', 'error')
    
    # Get user's active alerts
    alerts = Alert.query.filter_by(user_id=current_user.id).all()
    
    return render_template('alerts.html', 
                         secrets=secrets_list,
                         alerts=alerts,
                         selected_secrets=selected_secrets)

@app.route('/delete_alert', methods=['POST'])
@login_required
# Check id alert in DB
def delete_alert():
    alert_id = request.form.get('alert_id')
    alert = Alert.query.get(alert_id)
    
    if alert and alert.user_id == current_user.id:
        db.session.delete(alert)
        db.session.commit()
        flash('Alert deleted successfully', 'success')
    else:
        flash('Alert not found or unauthorized', 'error')
    
    return redirect(url_for('alerts'))

@app.route('/renewal', methods=['GET', 'POST'])
@login_required
def renewal():
    if not k8s_client:
        flash('Please upload a kubeconfig file first', 'error')
        return redirect(url_for('kubeconfig'))
    
    if request.method == 'POST':
        secret_name = request.form.get('secret_name')
        domain = request.form.get('domain')
        validity_days = int(request.form.get('validity_days', 90))
        
        try:
            namespace, name = secret_name.split('/')
            
            # Get the current secret
            secret = k8s_client.read_namespaced_secret(name, namespace)
            
            # Generate new certificate
            # Note: This is a placeholder for the actual certificate generation logic
            # You would need to implement this based on your certificate provider
            new_cert = generate_certificate(domain, validity_days)
            
            # Update the secret
            secret.data['tls.crt'] = base64.b64encode(new_cert['certificate']).decode('utf-8')
            secret.data['tls.key'] = base64.b64encode(new_cert['private_key']).decode('utf-8')
            
            k8s_client.replace_namespaced_secret(name, namespace, secret)
            
            # Record the renewal
            renewal = CertificateRenewal(
                secret_name=secret_name,
                domain=domain,
                validity_days=validity_days,
                status='success',
                user_id=current_user.id
            )
            db.session.add(renewal)
            db.session.commit()
            
            flash('Certificate renewed successfully', 'success')
            return redirect(url_for('renewal'))
            
        except Exception as e:
            # Record failed renewal
            renewal = CertificateRenewal(
                secret_name=secret_name,
                domain=domain,
                validity_days=validity_days,
                status='failed',
                user_id=current_user.id
            )
            db.session.add(renewal)
            db.session.commit()
            
            flash(f'Error renewing certificate: {str(e)}', 'error')
            return redirect(url_for('renewal'))
    
    # Get all secrets for the dropdown
    secrets_list = []
    if k8s_client:
        try:
            namespaces = k8s_client.list_namespace()
            for ns in namespaces.items:
                secrets = k8s_client.list_namespaced_secret(ns.metadata.name)
                for secret in secrets.items:
                    if secret.type == 'kubernetes.io/tls':
                        secrets_list.append({
                            'name': secret.metadata.name,
                            'namespace': secret.metadata.namespace
                        })
        except Exception as e:
            flash(f'Error fetching secrets: {str(e)}', 'error')
    
    # Get recent renewals
    renewals = CertificateRenewal.query.filter_by(user_id=current_user.id)\
        .order_by(CertificateRenewal.renewed_at.desc())\
        .limit(10)\
        .all()
    
    return render_template('renewal.html', 
                         secrets=secrets_list,
                         renewals=renewals)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/delete_kubeconfig', methods=['POST'])
@login_required
def delete_kubeconfig():
    config_id = request.form.get('config_id')
    kubeconfig = KubeConfig.query.get(config_id)
    
    if kubeconfig and kubeconfig.user_id == current_user.id:
        db.session.delete(kubeconfig)
        db.session.commit()
        
        # If this was the active kubeconfig, clear it
        global k8s_client
        if k8s_client:
            k8s_client = None
        
        flash('Cluster configuration deleted successfully', 'success')
    else:
        flash('Cluster configuration not found or unauthorized', 'error')
    
    return redirect(url_for('kubeconfig'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 
