import os
import sqlite3
import random
import string
import time
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, session
from werkzeug.utils import secure_filename
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv
from utils.checker import generate_pdf_report, tokenize_code, get_graphcodebert_embedding, compute_similarity_pair
import torch
from transformers import AutoTokenizer, AutoModel
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import tempfile
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
load_dotenv()

# Configuration
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'codecompare_uploads')
REPORT_FOLDER = os.path.join(tempfile.gettempdir(), 'codecompare_reports')
ALLOWED_EXTENSIONS = {'py', 'java', 'cpp', 'c', 'js', 'php'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# SQLite Database Setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, 
                  email TEXT UNIQUE, 
                  name TEXT, 
                  otp TEXT, 
                  otp_expiry INTEGER,
                  last_logout INTEGER)''')  # 👈 add this
    c.execute('''CREATE TABLE IF NOT EXISTS reports 
                 (id INTEGER PRIMARY KEY, 
                  user_id INTEGER, 
                  filename TEXT, 
                  created_at INTEGER)''')
    conn.commit()
    conn.close()

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


import smtplib
from email.mime.text import MIMEText

def send_otp_email(email, otp):
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))
    smtp_user = os.getenv('EMAIL_USER')
    smtp_pass = os.getenv('EMAIL_PASS')

    subject = 'Your CodeSim Login OTP'
    body = f'Your OTP is: {otp} (Valid for 5 minutes)'

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, email, msg.as_string())
        print(f"OTP sent to {email}")
        return True
    except Exception as e:
        print(f"Failed to send OTP: {str(e)}")
        return False

def send_welcome_email(email, name):
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))
    smtp_user = os.getenv('EMAIL_USER')
    smtp_pass = os.getenv('EMAIL_PASS')

    subject = "Welcome to CodeSim - Code Similarity Platform"
    body = f"""
    Hi {name},

    🎉 Thank you for signing up for CodeSim!

    CodeSim helps you compare code files using AI and generate      similarity reports with ease.

    You can now log in using your email and a secure OTP.

    Regards,  
    Team CodeSim
    """

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, email, msg.as_string())
        print(f"Welcome email sent to {email}")
        return True
    except Exception as e:
        print(f"Failed to send welcome email: {str(e)}")
        return False


# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip()
        name = request.form['name'].strip()

        # ✅ Domain check
        if not email.endswith('.christuniversity.in'):
            flash('Only @christuniversity.in email addresses are allowed.', 'error')
            return render_template('signup.html')

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        try:
            c.execute('INSERT INTO users (email, name) VALUES (?, ?)', (email, name))
            conn.commit()

            # ✅ Send Welcome Email
            send_welcome_email(email, name)

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.', 'error')
        finally:
            conn.close()

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        otp = request.form.get('otp', '').strip()

        # ✅ Domain check
        if not email.endswith('.christuniversity.in'):
            flash('Only @christuniversity.in email addresses are allowed.', 'error')
            return render_template('login.html', show_otp=False)

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        try:
            if otp:  # Verify OTP
                c.execute('SELECT id, otp, otp_expiry FROM users WHERE email = ?', (email,))
                user = c.fetchone()
                if user and user[1] == otp and user[2] > int(time.time()):
                    session['user_id'] = user[0]
                    c.execute('UPDATE users SET otp = NULL, otp_expiry = NULL WHERE email = ?', (email,))
                    conn.commit()
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid or expired OTP.', 'error')
                    return render_template('login.html', email=email, show_otp=True)

            else:  # First OTP request
                c.execute('SELECT id FROM users WHERE email = ?', (email,))
                user = c.fetchone()
                if user:
                    generated_otp = generate_otp()
                    expiry = int(time.time()) + 300  # 5 minutes
                    c.execute('UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?', (generated_otp, expiry, email))
                    print(f"[DEBUG] Stored OTP {generated_otp} for {email}, expires at {expiry}")
                    conn.commit()
                    send_otp_email(email, generated_otp)
                    flash('OTP sent to your email.', 'info')
                    return render_template('login.html', email=email, show_otp=True)
                else:
                    flash('Email not found. Please sign up first.', 'error')
        finally:
            conn.close()

    return render_template('login.html', show_otp=False)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    files = []
    results = []
    latest_report = None  # Track the latest report from this session
    if request.method == 'POST':
        if 'files' not in request.files:
            flash('No files uploaded.', 'error')
            return redirect(request.url)
        
        uploaded_files = request.files.getlist('files')
        file_type = request.form.get('file_type')
        if file_type not in ALLOWED_EXTENSIONS:
            flash('Invalid file type.', 'error')
            return redirect(request.url)
        
        # Save uploaded files
        for file in uploaded_files:
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                files.append({'filename': filename, 'content': content, 'ext': file_type})
            else:
                flash(f'Invalid file: {file.filename if file else "None"}', 'error')
        
        if len(files) < 2:
            flash('At least two files are required for comparison.', 'error')
            return redirect(request.url)
        
        # Compute similarity
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
        model = AutoModel.from_pretrained("microsoft/graphcodebert-base").to(device)
        embeddings = [get_graphcodebert_embedding(file['content'], tokenizer, model, device) for file in files]
        
        scores = []
        for i in range(len(files)):
            for j in range(i + 1, len(files)):
                result = compute_similarity_pair(i, j, files, embeddings, file_type)
                scores.append(result)
        
        # Generate PDF
        report_filename = f"report_{int(time.time())}.pdf"
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)
        generate_pdf_report(scores, report_path, len(files))
        
        # Save report to database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        current_time = int(time.time())
        c.execute('INSERT INTO reports (user_id, filename, created_at) VALUES (?, ?, ?)',
                  (session['user_id'], report_filename, current_time))
        conn.commit()
        conn.close()
        
        results = sorted(scores, key=lambda x: x['score'], reverse=True)
        latest_report = (report_filename, current_time)  # Store latest report
    
    # Get recent reports, filter existing files
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT filename, created_at FROM reports WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
              (session['user_id'],))
    reports = c.fetchall()
    conn.close()
    
    # Filter reports to only include existing files, exclude latest if from this session
    valid_reports = []
    for report in reports:
        report_path = os.path.join(app.config['REPORT_FOLDER'], report[0])
        if os.path.exists(report_path):
            if not latest_report or report[0] != latest_report[0]:  # Exclude latest report
                valid_reports.append(report)
            elif not latest_report:  # If no POST, include all valid reports
                valid_reports.append(report)
        else:
            flash(f'Report {report[0]} not found on server.', 'error')
    
    return render_template('dashboard.html', results=results, latest_report=latest_report, reports=valid_reports)

@app.route('/download/<filename>')
def download_report(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['REPORT_FOLDER'], filename, as_attachment=True)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        logout_time = int(time.time())
        c.execute('UPDATE users SET last_logout = ? WHERE id = ?', (logout_time, user_id))
        conn.commit()
        conn.close()
        session.pop('user_id')
        flash("Logged out successfully.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
