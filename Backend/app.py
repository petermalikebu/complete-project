import json
import csv
import os
import base64
from io import BytesIO
from datetime import datetime, timezone
import threading
import time
import schedule
from hashlib import sha256
from flask_mail import Mail, Message
from flask import (
    Flask,
    render_template,
    make_response,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file,
    Response
)
from flask_pymongo import PyMongo
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import qrcode
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyotp  # For TOTP-based MFA
import smtplib
from email.mime.text import MIMEText
from functools import wraps
from os import urandom
import tempfile
import schedule
import sys
import sendgrid
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash



# AES Key and RSA Key Initialization (global scope to allow rotation)
aes_key = AESGCM.generate_key(bit_length=256)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives AES key from password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_data: bytes, encryption_key: bytes) -> tuple:
    """Encrypts file data using AES-256-GCM."""
    # Generate a random nonce (12 bytes)
    nonce = os.urandom(12)

    # Create a Cipher object with AES-GCM
    aesgcm = AESGCM(aes_key)  # Use the global aes_key directly
    ciphertext = aesgcm.encrypt(nonce, file_data, None)

    return nonce, ciphertext

def decrypt_file(nonce: bytes, ciphertext: bytes, encryption_key: bytes) -> bytes:
    """Decrypts file data using AES-256-GCM and returns decrypted data."""
    aesgcm = AESGCM(aes_key)  # Use the global aes_key directly

    try:
        # Decrypt the binary data
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data
    except Exception as e:
        print(f"An error occurred while decrypting the file: {str(e)}")
        return None

def wrap_aes_key(aes_key: bytes, public_key) -> bytes:
    """Wraps AES key using RSA public key."""
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped_key

def unwrap_aes_key(wrapped_key: bytes, private_key) -> bytes:
    """Unwraps AES key using RSA private key."""
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Key rotation function
def rotate_keys():
    global aes_key, private_key, public_key
    print("Rotating keys...")

    # Rotate AES key
    aes_key = AESGCM.generate_key(bit_length=256)

    # Rotate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    print("Keys rotated successfully")

# Schedule the key rotation every 12 hours
# Uncomment the line below if you're using a scheduling library
# schedule.every(12).hours.do(rotate_keys)

def log_audit(action: str, user: str, details: str):
    """Logs an audit entry for the given action."""
    db.audit_logs.insert_one({
        "timestamp": datetime.now(timezone.utc),  # Use timezone-aware datetime
        "action": action,
        "user": user,
        "details": details
    })

# Flask app configuration
app = Flask(__name__, template_folder="../frontend/templates", static_folder="../frontend/static")
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/Database'
mongo = PyMongo(app)

# SendGrid Configuration
app.config['MAIL_SERVER'] = 'smt.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USENAME'] ='YOUR email id'
app.config['MAIL_PASSWORD'] = 'YOUR APP SPECIFIC PASSWORD'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
 


@app.route('/')
@app.route('/index')
def index():
    if 'email' in session:
        if session.get('user_role') == 'admin':
            return render_template('index.html', admin=True)
        else:
            return render_template('index.html', admin=False)
    else:
        flash("You need to log in first.")
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        role = request.form.get('role', 'user')  # Default to 'user' if not provided
        
        existing_user = mongo.db.users.find_one({'email': email})

        if existing_user:
            flash("User already exists.")
            return redirect(url_for('signup'))

        # If trying to sign up as admin, check the number of existing admins
        if role == 'admin':
            admin_count = mongo.db.users.count_documents({'role': 'admin'})
            if admin_count >= 2:
                flash("Maximum number of admin accounts reached. Cannot create more admins.")
                return redirect(url_for('signup'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Generate a new MFA secret for the user
        mfa_secret = pyotp.random_base32()

        # Insert user into the database with the mfa_secret
        mongo.db.users.insert_one({
            'email': email,
            'password': hashed_password,
            'phone': phone,
            'role': role,  # Assign the role during signup
            'verified': False,  # Default to False until MFA setup is completed
            'mfa_attempts': 0,  # Initialize MFA attempts
            'account_locked': False,  # Initialize account lock status
            'mfa_secret': mfa_secret  # Store the MFA secret
        })
        
          # Log the audit for user signup
        log_audit('User Signup', email, 'User signed up with phone number: ' + phone)

        flash("Signup successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = mongo.db.users.find_one({'email': email})

        if user:
            if user.get('account_locked', False):
                flash("Account is locked. Contact support.")
                return redirect(url_for('login'))

            if check_password_hash(user['password'], password):
                # Successful password check, check if MFA is needed
                if not user['verified']:  # MFA is needed
                    session['login_email'] = email
                    return redirect(url_for('mfa_setup'))  # Redirect to MFA setup
                else:
                    session['email'] = email
                    session['user_role'] = user.get('role', 'user')
                    return redirect(url_for('dashboard'))  # Redirect to dashboard
            else:
                flash("Invalid credentials.")
                return redirect(url_for('login'))
        else:
            flash("User does not exist.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/mfa_setup', methods=['GET', 'POST'])
def mfa_setup():
    if 'login_email' not in session:
        return redirect(url_for('login'))

    email = session['login_email']
    user = mongo.db.users.find_one({'email': email})

    if request.method == 'POST':
        mfa_code = request.form.get('mfa_code', '')
        totp = pyotp.TOTP(user['mfa_secret'])
        
        if totp.verify(mfa_code):
            # MFA code is correct
            session['email'] = email
            session['user_role'] = user.get('role', 'user')

            # Mark the user as verified after successful MFA
            mongo.db.users.update_one({'email': email}, {'$set': {'verified': True}})
            return redirect(url_for('dashboard'))  # Redirect to dashboard

        else:
            # Increment MFA attempts on failure
            mongo.db.users.update_one(
                {'email': email},
                {'$inc': {'mfa_attempts': 1}}
            )
            user = mongo.db.users.find_one({'email': email})

            if user['mfa_attempts'] >= 5:
                mongo.db.users.update_one(
                    {'email': email},
                    {'$set': {'account_locked': True}}
                )
                flash("Account is locked due to too many failed MFA attempts.")
                return redirect(url_for('login'))
            else:
                flash("Invalid MFA code. Please try again.")
                return redirect(url_for('mfa_setup'))

    totp = pyotp.TOTP(user['mfa_secret'])
    qr_url = totp.provisioning_uri(name=email, issuer_name="SecureFile")

    qr = qrcode.make(qr_url)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_image_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    return render_template('mfa_setup.html', qr_image_base64=qr_image_base64)

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        return render_template('dashboard.html')
    else:
        flash("You need to log in first.")
        return redirect(url_for('login'))
    


# Allowed file extensions and max file size (5 MB)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def file_size_ok(file):
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)  # Reset file pointer
    return file_length <= MAX_FILE_SIZE

def get_current_user_role():
    return session.get('user_role', 'guest')



# Make sure you have the correct `requires_role` decorator
def requires_role(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Assuming `get_current_user_role` is a function that retrieves the user's role
            if get_current_user_role() != role:
                flash("You do not have permission to perform this action.", "danger")
                return redirect(url_for('index'))  # Or any other route
            return f(*args, **kwargs)
        return wrapped
    return decorator

def test_promote_user(client):
    response = client.post('/promote_user/user@example.com')
    assert response.status_code == 302  # Check for redirect
    assert b'admin' in response.data  # Check for 'admin' in response

def test_demote_user(client):
    response = client.post('/demote_user/admin@example.com')
    assert response.status_code == 302  # Check for redirect
    assert b'user' in response.data  # Check for 'user' in response


@app.route('/promote_user/<email>', methods=['POST'])
@requires_role('admin')  
def promote_user(email):
    # Check if the user exists
    user = mongo.db.users.find_one({'email': email})
    if user:
        # Update the user's role to 'admin'
        mongo.db.users.update_one({'email': email}, {'$set': {'role': 'admin'}})
        flash(f"User {email} has been promoted to admin.", "success")
    else:
        flash(f"User {email} does not exist.", "danger")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/demote_user/<email>', methods=['POST'])
@requires_role('admin')
def demote_user(email):
    # Check if the user exists
    user = mongo.db.users.find_one({'email': email})
    if user:
        # Update the user's role to 'user' (or any lower role)
        mongo.db.users.update_one({'email': email}, {'$set': {'role': 'user'}})
        flash(f"User {email} has been demoted to user.", "success")
    else:
        flash(f"User {email} does not exist.", "danger")
    
    return redirect(url_for('admin_dashboard'))


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
    Handle file upload and encryption using AES-256-GCM.

    This view function expects a POST request with a file and a password.
    It checks if the user is logged in, if the file is in the allowed extensions,
    and if the file size is within the limit.

    If the file is valid, it derives the AES key from the user-provided password
    using the PBKDF2-HMAC-SHA256 algorithm, reads the file content, encrypts the
    file using AES-256-GCM, and stores the encrypted file in the MongoDB database
    along with the hashed password and salt for later validation.

    If the file is invalid, it flashes an error message and redirects to the
    dashboard.

    If the request is a GET request, it renders the upload.html template to
    allow the user to upload a file.
    """
    if 'email' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part in the request.")
            return redirect(url_for('dashboard'))

        file = request.files['file']

        if file.filename == '':
            flash("No selected file.")
            return redirect(url_for('dashboard'))

        if file and allowed_file(file.filename) and file_size_ok(file):
            filename = secure_filename(file.filename)
            password = request.form.get('password')

            # Derive the AES key from the user-provided password
            salt = os.urandom(16)  # Generate a random salt for key derivation
            aes_key = derive_key(password, salt)  # Use the derive_key function to get the AES key

            # Read the file content
            file.seek(0)  # Reset file pointer after checking size
            file_data = file.read()

            # Encrypt the file using AES-256-GCM
            nonce, ciphertext = encrypt_file(file_data, aes_key)

            # Hash the password for later validation (storing salt for future use)
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            # Update MongoDB schema when inserting a file
            mongo.db.files.insert_one({
                'filename': filename,
                'nonce': nonce,
                'ciphertext': ciphertext,
                'uploaded_by': session['email'],
                'password_hash': hashed_password.decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8'),  # Store the salt for deriving the key later
                'failed_attempts': 0,
                'locked': False,
                'timestamp': datetime.utcnow()
            })

            flash("File uploaded successfully.")
            return redirect(url_for('my_files'))
        else:
            flash("Invalid file type or file size exceeds the limit.")
            return redirect(url_for('dashboard'))

    return render_template('upload.html')


@app.route('/my_files', methods=['GET', 'POST'])
def my_files():
    if 'email' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    user_email = session['email']
    files = list(mongo.db.files.find({"uploaded_by": user_email}))
    files_count = mongo.db.files.count_documents({"uploaded_by": user_email})
    
    if request.method == 'POST':
        file_id = request.form['file_id']
        action_password = request.form.get('download_password') or request.form.get('delete_password')
        file = mongo.db.files.find_one({"_id": ObjectId(file_id), "uploaded_by": user_email})

        if file:
            stored_password_hash = file.get('password_hash')
            failed_attempts = file.get('failed_attempts', 0)
            locked = file.get('locked', False)
            salt = base64.b64decode(file.get('salt'))  # Retrieve the stored salt

            if locked:
                flash("This file is locked due to too many failed attempts. Please contact the admin.")
                return redirect(url_for('my_files'))

            # Verify password
            if stored_password_hash and bcrypt.checkpw(action_password.encode(), stored_password_hash.encode()):
                # Reset failed attempts upon successful verification
                mongo.db.files.update_one(
                    {"_id": ObjectId(file_id)},
                    {"$set": {"failed_attempts": 0}}
                )

                # Handle download request
                if 'download' in request.form:
                    try:
                        nonce = bytes(file['nonce'])
                        ciphertext = bytes(file['ciphertext'])
                        aes_key = derive_key(action_password, salt)  # Derive the AES key using the provided password and the stored salt
                        filename = file['filename']

                        # Decrypt the file data
                        decrypted_data = decrypt_file(nonce, ciphertext, aes_key)

                        if decrypted_data:
                            # Create a temporary file for the decrypted data
                            output_path = os.path.join(tempfile.gettempdir(), filename)
                            with open(output_path, 'wb') as decrypted_file:
                                decrypted_file.write(decrypted_data)

                            return send_file(
                                output_path,
                                as_attachment=True,
                                download_name=filename,
                                mimetype='application/octet-stream'
                            )
                        else:
                            flash("Failed to decrypt the file. Please check the password.")
                    except Exception as e:
                        flash(f"An error occurred while decrypting the file: {str(e)}")

                # Handle delete request
                elif 'delete' in request.form:
                    mongo.db.files.delete_one({"_id": ObjectId(file_id)})
                    mongo.db.audit_logs.insert_one({
                        "timestamp": datetime.now(),
                        "action": "Deleted file",
                        "user": user_email,
                        "details": f"Deleted file ID: {file_id}, filename: {file['filename']}"
                    })
                    flash("File deleted successfully.")

            else:
                # Increment failed attempts if password is incorrect
                failed_attempts += 1
                if failed_attempts >= 3:
                    # Lock the file after 3 failed attempts
                    mongo.db.files.update_one(
                        {"_id": ObjectId(file_id)},
                        {"$set": {"locked": True}}
                    )
                    flash("The file has been locked due to too many failed attempts. Please contact the admin.")
                else:
                    # Update the failed attempts count
                    mongo.db.files.update_one(
                        {"_id": ObjectId(file_id)},
                        {"$set": {"failed_attempts": failed_attempts}}
                    )
                    flash(f"Invalid password. You have {3 - failed_attempts} attempt(s) remaining.")

            return redirect(url_for('my_files'))

    return render_template('my_files.html', files=files, files_count=files_count)

@app.route('/share', methods=['GET', 'POST'])
def share_file():
    if 'email' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        recipient_email = request.form.get('recipient_email')
        encryption_key = request.form.get('encryption_key')

        # Validate inputs
        if not file or not recipient_email or not encryption_key:
            flash("Please provide all required fields.")
            return redirect(url_for('share_file'))

        # Verify encryption key length
        if len(encryption_key) < 8:
            flash("Encryption key must be at least 8 characters long.")
            return redirect(url_for('share_file'))

        # Verify recipient exists
        recipient = mongo.db.users.find_one({'email': recipient_email})
        if not recipient:
            flash("Recipient not found.")
            return redirect(url_for('share_file'))

        # Encrypt and store the file (use existing encryption function)
        filename = secure_filename(file.filename)
        aes_key = sha256(encryption_key.encode()).digest()
        file_data = file.read()
        nonce, ciphertext = encrypt_file(file_data, aes_key)

        hashed_key = bcrypt.hashpw(encryption_key.encode(), bcrypt.gensalt()).decode('utf-8')

        # Store the file with metadata
        mongo.db.files.insert_one({
            'filename': filename,
            'nonce': nonce,
            'ciphertext': ciphertext,
            'sender': session['email'],
            'recipient': recipient_email,
            'delete_password': hashed_key,
            'access_attempts': 0,
            'status': 'pending',
            'timestamp': datetime.utcnow()
        })

        # Send email notification using SendGrid
        send_email_notification(recipient_email, filename, session['email'])

        # Log sharing action
        mongo.db.audit_logs.insert_one({
            'timestamp': datetime.utcnow(),
            'action': 'File Shared',
            'user': session['email'],
            'details': f"Shared file '{filename}' with {recipient_email}."
        })

        flash(f"File '{filename}' shared with {recipient_email}. Notification sent to the recipient.")
        return redirect(url_for('dashboard'))

    return render_template('share.html')


def send_email_notification(recipient_email, filename, sender_email):
    """Sends a real-time email notification to the recipient when a file is shared."""
    message = Mail(
        from_email='your_email@example.com',  # Replace with your verified SendGrid sender email
        to_emails=recipient_email,
        subject="You have received a new file!",
        html_content=f"""
        <p>Hello,</p>
        <p>You have received a file named '<strong>{filename}</strong>' from <strong>{sender_email}</strong>.</p>
        <p>Please log in to your DataFortress account to access the file.</p>
        <p>Thank you,<br>DataFortress Team</p>
        """
    )

    try:
        sg = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
        sg.send(message)
        print(f"Email sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")


@app.route('/received_files', methods=['GET'])
def received_files():
    if 'email' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    user_email = session['email']
    shared_files = list(mongo.db.files.find({'recipient': user_email, 'status': 'pending'}))

    # Log the action of viewing received files
    mongo.db.audit_logs.insert_one({
        'timestamp': datetime.utcnow(),
        'action': 'View Received Files',
        'user': session['email'],
        'details': "Viewed received files."
    })

    return render_template('received_files.html', shared_files=shared_files)

@app.route('/download_shared_file/<file_id>', methods=['POST'])
def download_shared_file(file_id):
    if 'email' not in session:
        flash("You do not have permission to access this.")
        return redirect(url_for('dashboard'))

    # Fetch the file record from the database
    file_record = mongo.db.files.find_one({'_id': ObjectId(file_id), 'recipient': session['email']})
    if not file_record:
        flash("File not found or you don't have access to it.")
        return redirect(url_for('received_files'))

    encryption_key = request.form.get('encryption_key')

    # Increment access attempts
    access_attempts = file_record.get('access_attempts', 0)

    # Check if the encryption key matches the hashed key
    if bcrypt.checkpw(encryption_key.encode(), file_record['delete_password'].encode()):
        try:
            # Decrypt the file using the provided encryption key
            aes_key = sha256(encryption_key.encode()).digest()
            nonce = bytes(file_record['nonce'])  # Ensure this is bytes
            ciphertext = bytes(file_record['ciphertext'])  # Ensure this is bytes

            # Get the decrypted data
            decrypted_data = decrypt_file(nonce, ciphertext, aes_key)
            if decrypted_data is None:
                raise ValueError("Decryption failed.")

            # Log the successful download action
            mongo.db.audit_logs.insert_one({
                'timestamp': datetime.utcnow(),
                'action': 'Download Shared File',
                'user': session['email'],
                'details': f"Downloaded shared file '{file_record['filename']}' successfully."
            })

            # Reset access attempts to zero on successful download
            mongo.db.files.update_one(
                {'_id': ObjectId(file_id)},
                {'$set': {'access_attempts': 0}}
            )

            # Send the decrypted file to the user
            return send_file(
                BytesIO(decrypted_data),
                as_attachment=True,
                download_name=file_record['filename']
            )

        except Exception as e:
            flash(f"An error occurred while decrypting the file: {str(e)}")
            return redirect(url_for('received_files'))

    else:
        # Increment the access attempt counter
        access_attempts += 1
        mongo.db.files.update_one(
            {'_id': ObjectId(file_id)},
            {'$set': {'access_attempts': access_attempts}}
        )

        if access_attempts >= 2:
            # Automatically delete the file after two failed attempts
            mongo.db.files.delete_one({'_id': ObjectId(file_id)})

            # Log the deletion
            mongo.db.audit_logs.insert_one({
                'timestamp': datetime.utcnow(),
                'action': 'File Deleted Due to Failed Attempts',
                'user': session['email'],
                'details': f"File '{file_record['filename']}' deleted after multiple failed decryption attempts."
            })

            flash("You have exceeded the maximum number of attempts. The file has been deleted.")
            return redirect(url_for('received_files'))

        flash("Decryption failed. Please check your encryption key.")
        return redirect(url_for('received_files'))


# Profile route should be outside the download_file function
@app.route('/profile')
@requires_role('user')
def profile():
    if 'email' in session:
        user = mongo.db.users.find_one({'email': session['email']})
        return render_template('profile.html', user=user)
    else:
        flash("You do  not have permission to access this.")
        return redirect(url_for('dashboard'))
    
@requires_role('user')
def profile():
    if 'email' in session:
        user = mongo.db.users.find_one({'email': session['email']})
        return render_template('profile.html', user=user)
    else:
        flash("You do not have permission to access this.")
        return redirect(url_for('dashboard'))
    
@app.route('/admin')
@requires_role('admin')
def admin_dashboard():
    if 'email' in session:
        files = mongo.db.files.find()
        users = mongo.db.users.find()
        return render_template('admin_dashboard.html', files=files, users=users)
    else:
        flash("You do not have permission to access this.")
        return redirect(url_for('dashboard'))
    
# Assume you have a function that checks user roles
@app.route('/audit_logs', methods=['GET', 'POST'])
@requires_role('admin')
def view_audit_logs():
    if 'email' in session:
        # Fetch all audit logs from MongoDB
        logs = list(mongo.db.audit_logs.find().sort('timestamp', -1))

        if request.method == 'POST':
            # Handle CSV download
            def generate_csv():
                yield 'Timestamp,Action,User,Details\n'
                for log in logs:
                    yield f"{log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')},{log['action']},{log['user']},{log['details']}\n"

            response = Response(generate_csv(), mimetype='text/csv')
            response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
            return response

        # Render the template with the logs for viewing
        return render_template('audit_logs.html', logs=logs)
    else:
        flash("You Do not have the permission to access this.")
        return redirect(url_for('dashboard'))
    
@app.route('/export_audit_logs_csv', methods=['POST'])
@requires_role('admin')
def export_audit_logs_csv():
    # Fetch all audit logs from MongoDB
    logs = list(mongo.db.audit_logs.find().sort('timestamp', -1))

    # Function to generate CSV content
    def generate_csv():
        yield 'Timestamp,Action,User,Details\n'
        for log in logs:
            yield f"{log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')},{log['action']},{log['user']},{log['details']}\n"

    # Create and return the CSV response
    response = Response(generate_csv(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
    return response()


@app.route('/user-education')
def user_education():
    return render_template('user_education.html')

@app.route('/features', endpoint='features_page')
@app.route('/features')
def features():
    return render_template('features.html')  # Adjust to your actual template

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')


@app.route('/report_logs', methods=['GET', 'POST'])
@requires_role('user')
def report_logs():
    if 'email' in session:
        user_email = session['email']
        user = mongo.db.users.find_one({'email': user_email})
        
        # Check if user has a report logs password set
        if not user.get('report_logs_password'):
            # If no password is set, redirect to set password page
            return redirect(url_for('set_report_logs_password'))
        
        # Handle report logs login
        if request.method == 'POST':
            input_password = request.form.get('password')
            if check_password_hash(user['report_logs_password'], input_password):
                # Fetch user-specific logs from audit logs
                logs = list(mongo.db.audit_logs.find({'user': user_email}).sort('timestamp', -1))
                return render_template('user_report_logs.html', logs=logs)
            else:
                flash("Incorrect password. Please try again.", "danger")
        
        return render_template('report_logs_login.html')  # Render login form if GET request
    else:
        flash("You do not have permission to access this.")
        return redirect(url_for('dashboard_base'))

@app.route('/set_report_logs_password', methods=['GET', 'POST'])
@requires_role('user')
def set_report_logs_password():
    if 'email' in session:
        user_email = session['email']
        
        if request.method == 'POST':
            new_password = request.form.get('password')
            hashed_password = generate_password_hash(new_password)
            
            # Update user's report logs password in the database
            mongo.db.users.update_one({'email': user_email}, {'$set': {'report_logs_password': hashed_password}})
            flash("Password set successfully. Please log in to view your report logs.", "success")
            return redirect(url_for('report_logs'))
        
        return render_template('set_report_logs_password.html')
    else:
        flash("You do not have permission to access this.")
        return redirect(url_for('dashboard_base'))

def log_audit(action, user, details):
    mongo.db.audit_logs.insert_one({
        'timestamp': datetime.utcnow(),
        'action': action,
        'user': user,
        'details': details
    })



@app.route('/logout', methods=['GET'])
def logout():
    session.pop('email', None)
    session.pop('user_role', None)
    flash("Logged out successfully.")
    return redirect(url_for('index'))


if __name__ == '__main__':
    # Start key rotation thread
    threading.Thread(target=schedule.run_pending, daemon=True).start()
    
    # Run the Flask app on a custom port (e.g., 5001)
    app.run(debug=True, host='0.0.0.0', port=3000)  # Change to 3000 or another available port

