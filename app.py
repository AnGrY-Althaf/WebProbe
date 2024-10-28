import html
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from bs4 import BeautifulSoup
from xhtml2pdf import pisa
from io import BytesIO
import json
import os
import urllib.parse
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    scans = db.relationship('Scan', backref='user', lazy=True)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    result = db.Column(db.Text, nullable=False)
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
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. You can now login!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Check your credentials.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', username=current_user.username, scans=scans)


class VulnerabilityScanner:
    def __init__(self, url, payload_file="payloads.json"):
        self.url = url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payloads = self.load_payloads(payload_file)

    def load_payloads(self, payload_file):
        if os.path.exists(payload_file):
            with open(payload_file, 'r') as file:
                return json.load(file)
        return {"sqli": [], "xss": []}

    def get_forms(self):
        try:
            response = self.session.get(self.url)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"Error fetching forms: {e}")
            return []

    def test_sql_injection(self, form):
        sqli_payloads = self.payloads.get("sqli", [])
        form_action = form.get('action') if form.get('action') else self.url
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')

        for payload in sqli_payloads:
            form_data = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                input_value = input_tag.get('value', '')

                if input_type == 'text':
                    form_data[input_name] = payload  # Inject payload here
                else:
                    form_data[input_name] = input_value

            if method == 'post':
                response = self.session.post(self.url + form_action, data=form_data)
            else:
                response = self.session.get(self.url + form_action, params=form_data)

            if any(error in response.text.lower() for error in [
                "sql syntax", "mysql_fetch", "syntax error", 
                "unclosed quotation", "sqlstate", "error in your sql syntax",
                "you have an error in your sql syntax", "database error"]):
                self.vulnerabilities.append(f"SQL Injection vulnerability found at  {self.url + form_action}  with payload:  {payload}")
                return True
        return False

    def test_xss(self, form):
        xss_payloads = self.payloads.get("xss", [])
        form_action = form.get('action') if form.get('action') else self.url
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')

        for payload in xss_payloads:
            form_data = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                input_value = input_tag.get('value', '')

                if input_type == 'text':
                    form_data[input_name] = payload  # Inject payload here
                else:
                    form_data[input_name] = input_value

            if method == 'post':
                response = self.session.post(self.url + form_action, data=form_data)
            else:
                response = self.session.get(self.url + form_action, params=form_data)

            if payload in response.text:
                self.vulnerabilities.append(f"XSS vulnerability found at {self.url + form_action} with payload: {payload}")
                return True
        return False

    def test_sql_injection_in_url(self):
        sqli_payloads = self.payloads.get("sqli", [])
        parsed_url = urllib.parse.urlparse(self.url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        for payload in sqli_payloads:
            test_params = {param: payload for param in query_params}
            response = self.session.get(self.url, params=test_params)

            if any(error in response.text.lower() for error in [
                "sql syntax", "mysql_fetch", "syntax error", 
                "unclosed quotation", "sqlstate", "error in your sql syntax",
                "you have an error in your sql syntax", "database error"]):
                self.vulnerabilities.append(f"SQL Injection vulnerability found at {self.url} with payload: {payload}")
                return True
        return False

    def check_security_headers(self):
        try:
            response = self.session.get(self.url)
            headers = response.headers

            if "Content-Security-Policy" not in headers:
                self.vulnerabilities.append(f"Missing Content-Security-Policy (CSP) header at  {self.url}")
            if "Strict-Transport-Security" not in headers:
                self.vulnerabilities.append(f"Missing Strict-Transport-Security (HSTS) header at  {self.url}")
            if "X-Frame-Options" not in headers:
                self.vulnerabilities.append(f"Missing X-Frame-Options header at  {self.url}")
            if "X-XSS-Protection" not in headers:
                self.vulnerabilities.append(f"Missing X-XSS-Protection header at  {self.url}")
            if "X-Content-Type-Options" not in headers:
                self.vulnerabilities.append(f"Missing X-Content-Type-Options header at  {self.url}")

        except Exception as e:
            print(f"Error checking headers: {e}")

    def run(self):
        self.check_security_headers()

        forms = self.get_forms()
        for form in forms:
            self.test_sql_injection(form)
            self.test_xss(form)

        self.test_sql_injection_in_url()

        return self.vulnerabilities


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        try:
            # Check if the request is JSON or form data
            if request.is_json:
                data = request.get_json()
                url = data.get('url')
            else:
                url = request.form.get('url')
            
            if not url:
                return jsonify({'error': 'URL is required'}), 400

            # Perform vulnerability scan
            scanner = VulnerabilityScanner(url)
            vulnerabilities = scanner.run()

            # Save the scan result to the database
            scan_result = Scan(
                url=url,
                result="\n".join(vulnerabilities),
                user_id=current_user.id
            )
            db.session.add(scan_result)
            db.session.commit()

            # If it's an AJAX request, return JSON
            if request.is_json:
                return jsonify({
                    'success': True,
                    'scan_id': scan_result.id,
                    'vulnerabilities': vulnerabilities
                })
            
            # If it's a regular form submit, render the results template
            return render_template('scan_results.html', 
                                url=url, 
                                vulnerabilities=vulnerabilities, 
                                scan_id=scan_result.id)

        except Exception as e:
            if request.is_json:
                return jsonify({'error': str(e)}), 500
            flash(f'Error during scan: {str(e)}', 'danger')
            return redirect(url_for('scan'))

    # GET request - show the scan form
    return render_template('scan.html')


@app.route('/scan/<int:scan_id>/report')
@login_required
def generate_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Get the current date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Process vulnerabilities and categorize them
    raw_vulnerabilities = scan.result.split("\n") if scan.result else []
    
    # Initialize counters
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    # Process vulnerabilities into structured format
    processed_vulnerabilities = []
    for vuln in raw_vulnerabilities:
        vuln_data = {
            'name': 'Security Issue',
            'severity': 'Low',
            'description': vuln,
            'impact': 'Could potentially impact system security',
            'affected_component': 'Web Application',
            'remediation': 'Please review and patch the identified vulnerability',
            'references': []
        }
        
        # Categorize based on vulnerability type
        if 'SQL Injection' in vuln:
            vuln_data.update({
                'name': 'SQL Injection Vulnerability',
                'severity': 'Critical',
                'impact': 'Could allow unauthorized database access and manipulation',
                'remediation': 'Use parameterized queries, input validation, and proper escaping',
                'references': [{'url': 'https://owasp.org/www-community/attacks/SQL_Injection', 'title': 'OWASP SQL Injection'}]
            })
            critical_count += 1
        elif 'XSS' in vuln:
            vuln_data.update({
                'name': 'Cross-Site Scripting (XSS)',
                'severity': 'High',
                'impact': 'Could allow execution of malicious scripts in user browsers',
                'remediation': 'Implement proper input/output encoding and Content Security Policy',
                'references': [{'url': 'https://owasp.org/www-community/attacks/xss/', 'title': 'OWASP XSS'}]
            })
            high_count += 1
        elif 'Missing' in vuln:
            vuln_data.update({
                'name': 'Missing Security Header',
                'severity': 'Medium',
                'impact': 'Could increase vulnerability to various attacks',
                'remediation': 'Implement appropriate security headers in server configuration',
                'references': [{'url': 'https://owasp.org/www-project-secure-headers/', 'title': 'OWASP Secure Headers Project'}]
            })
            medium_count += 1
        else:
            low_count += 1
            
        processed_vulnerabilities.append(vuln_data)
    
    # Calculate security score
    total_vulns = len(processed_vulnerabilities)
    if total_vulns == 0:
        security_score = 100
    else:
        weighted_score = (low_count * 0.1 + medium_count * 0.3 + high_count * 0.6 + critical_count * 0.9)
        security_score = max(0, round(100 - (weighted_score / total_vulns * 100)))
    
    try:
        # Generate HTML
        html_content = render_template(
            'report_template.html',
            url=scan.url,
            vulnerabilities=processed_vulnerabilities,
            current_datetime=current_datetime,
            security_score=security_score,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            scan_duration="1 minute"
        )
        
        # Create PDF
        pdf = BytesIO()
        
        # Convert HTML to PDF
        pisa_status = pisa.CreatePDF(
            src=html_content.encode('UTF-8'),  # Convert the HTML to bytes
            dest=pdf,
            encoding='UTF-8'
        )
        
        # Check if PDF generation was successful
        if pisa_status.err:
            return 'Error generating PDF', 500
            
        # Reset the pointer of BytesIO
        pdf.seek(0)
        
        # Generate unique filename
        filename = f"Security_Scan_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        return send_file(
            pdf,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        return f'Error generating PDF: {str(e)}', 500



if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)