import os
import re
from flask import render_template, request, redirect, url_for, flash, session, abort, send_from_directory
from app import app, supabase
from werkzeug.utils import secure_filename
import bcrypt
import datetime
from cryptography.fernet import Fernet
import base64
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_role' not in session or session['user_role'] != 'admin':
            flash('Access denied. Admins only.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.errorhandler(403)
def forbidden(e):
    return redirect(url_for('dashboard'))

@app.route('/static/uploads/<filename>')
def serve_uploaded_file(filename):
    app.logger.info(f"Serving file: {filename}")
    return send_from_directory('static/uploads', filename)

# Generate a key for encryption
secret_key = base64.urlsafe_b64encode(Fernet.generate_key())

def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email)

def sanitize_input(input_string):
    return input_string.replace('<', '&lt;').replace('>', '&gt;')

def validate_message(message):
    if len(message) > 500:  # Example limit
        flash('Message exceeds the maximum length of 500 characters.', 'danger')
        return False
    return True

@app.route('/')
def home():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        role = request.form.get('role', 'user')  # Default role is 'user'

        if not is_valid_email(email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('register'))

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        app.logger.info(f"Registering user with email: {email}, name: {name}, role: {role}")

        try:
            # Send registration data to Supabase
            response = supabase.table('users').insert({
                'email': email,
                'name': name,
                'password': hashed_password.decode('utf-8'),
                'role': role,
                'created_at': datetime.datetime.now().isoformat()
            }).execute()

            app.logger.info(f"Supabase insert response: {response}")

            if response.data:  # Check for successful insertion
                app.logger.info(f"User inserted: {response.data}")
                flash('Registration successful! Please log in.', 'success')
            else:
                flash(f'Registration failed: {response.error}', 'danger')

            return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Registration failed: {str(e)}")
            flash(f'Registration failed: {str(e)}', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()  # Normalize email to lowercase
        password = request.form.get('password')

        if not email or not password:
            flash('Please provide both email and password.', 'danger')
            return redirect(url_for('login'))

        app.logger.info(f"Attempting to log in user with email: {email}")

        try:
            response = supabase.table('users').select('*').eq('email', email).execute()
            app.logger.info(f"Supabase user lookup response: {response}")

            user = response.data  # Directly access the data attribute

            app.logger.info(f"User data retrieved: {user}")

            if not user:
                flash('Login failed: Invalid email or password.', 'danger')
                return redirect(url_for('login'))

            stored_password = user[0].get('password')
            user_role = user[0].get('role')

            if not stored_password:
                flash('Login failed: No password set for this user.', 'danger')
                return redirect(url_for('login'))

            app.logger.info(f"Comparing provided password with stored password: {stored_password}")

            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                session['user_email'] = user[0]['email']
                session['user_role'] = user_role

                app.logger.info(f"User {email} logged in successfully.")
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Login failed: Invalid email or password.', 'danger')
                app.logger.info("Login failed: Password mismatch.")

        except Exception as e:
            app.logger.error(f"Login failed: {str(e)}")
            flash(f'Login failed: {str(e)}', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    user_email = session.get('user_email')
    if not user_email:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    # Accessing user data
    response = supabase.table('users').select('*').eq('email', user_email).execute()
    user_data = response.data[0] if response.data else None  # Safely accessing data

    if user_data is None:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=user_data)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    user_email = session.get('user_email')
    if not user_email:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    response = supabase.table('users').select('*').eq('email', user_email).execute()
    user_data = response.data[0] if response.data else None

    if user_data is None:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        app.logger.info('Upload POST request received.')
        
        if 'file' not in request.files:
            app.logger.warning('No file part in the request.')
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            app.logger.warning('No selected file.')
            flash('No selected file', 'danger')
            return redirect(request.url)

        app.logger.info(f'File received: {file.filename}')
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_folder = app.config['UPLOAD_FOLDER']
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            file_path = os.path.join(upload_folder, filename)
            app.logger.info(f'Saving file to: {file_path}')
            try:
                file.save(file_path)
                app.logger.info(f'File uploaded successfully: {file_path}')
                flash('File uploaded successfully', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                app.logger.error(f'Error saving file: {str(e)}')
                flash('Error saving file: ' + str(e), 'danger')
        else:
            app.logger.warning('Invalid file type.')
            flash('Invalid file type. Allowed types: png, jpg, jpeg, gif, pdf.', 'danger')

    return render_template('upload.html', user=user_data)

@app.route('/user_profile')
def user_profile():
    user_email = session.get('user_email')
    if not user_email:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    # Accessing user data
    response = supabase.table('users').select('*').eq('email', user_email).execute()
    user_data = response.data[0] if response.data else None

    if user_data is None:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    return render_template('user_profile.html', user=user_data)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    user_email = session.get('user_email')
    if not user_email:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    # Accessing user data
    response = supabase.table('users').select('*').eq('email', user_email).execute()
    user_data = response.data[0] if response.data else None

    if user_data is None:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')

        if email != user_data['email'] and supabase.table('users').select('*').eq('email', email).execute().data:
            flash('Email is already in use.', 'danger')
            return redirect(url_for('edit_profile'))

        if not is_valid_email(email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('edit_profile'))

        try:
            supabase.table('users').update({
                'name': name,
                'email': email
            }).eq('id', user_data['id']).execute()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user_profile'))
        except Exception as e:
            flash(f'Error updating profile: {str(e)}', 'danger')

    return render_template('edit_profile.html', user=user_data)

@app.route('/send_message', methods=['POST'])
def send_message():
    sender = session.get('user_email')
    recipient = request.form.get('recipient')
    message = request.form.get('message')
    file = request.files.get('file')

    if not sender or not recipient or not message:
        flash('All fields are required!', 'danger')
        return redirect(url_for('view_messages'))

    if not is_valid_email(recipient):
        flash('Invalid email format for recipient.', 'danger')
        return redirect(url_for('view_messages'))

    message = sanitize_input(message)

    if not validate_message(message):
        return redirect(url_for('view_messages'))

    file_name = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        file.save(os.path.join(upload_folder, filename))
        file_name = filename

    try:
        response = supabase.table('messages').insert({
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'file_name': file_name,
            'created_at': datetime.datetime.now().isoformat()
        }).execute()

        if response.data:  # Use response.data to check for successful insertion
            flash('Message sent successfully!', 'success')
        else:
            flash('Failed to send message: ' + str(response.error), 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')

    return redirect(url_for('view_messages'))

@app.route('/messages', methods=['GET'])
def view_messages():
    try:
        user_email = session.get('user_email')

        if not user_email:
            flash('You need to be logged in to view messages.', 'danger')
            return redirect(url_for('login'))

        # Accessing user data
        user_response = supabase.table('users').select('*').eq('email', user_email).execute()
        user = user_response.data[0] if user_response.data else None

        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))

        # Accessing messages
        messages_response = supabase.table('messages').select('*').eq('recipient', user_email).execute()
        messages = messages_response.data or []

        return render_template('messages.html', messages=messages, user=user)

    except Exception as e:
        flash(f"Error fetching messages: {str(e)}", 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/messages', methods=['GET'])
@admin_required
def admin_manage_messages():
    try:
        user_email = session.get('user_email')
        user_data = supabase.table('users').select('*').eq('email', user_email).execute().data[0]

        messages = supabase.table('messages').select('*').execute().data
        return render_template('admin_messages.html', messages=messages, user=user_data)
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/messages/delete/<message_id>', methods=['POST'])
def delete_message(message_id):
    try:
        supabase.table('messages').delete().eq('id', message_id).execute()
        flash('Message deleted successfully!', 'success')
    except Exception as e:
        flash(f'Deletion failed: {str(e)}', 'danger')

    return redirect(url_for('admin_manage_messages'))

@app.route('/admin/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    user_email = session.get('user_email')

    if not user_email:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    user_data = supabase.table('users').select('*').eq('email', user_email).execute().data[0]

    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        role = request.form.get('role', 'user')  # Default role is 'user'

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            supabase.table('users').insert({
                'email': email,
                'name': name,
                'password': hashed_password.decode('utf-8'),
                'role': role,
                'created_at': datetime.datetime.now().isoformat()
            }).execute()

            flash('User added successfully!', 'success')
            return redirect(url_for('admin_manage_users'))
        except Exception as e:
            flash(f'Failed to add user: {str(e)}', 'danger')

    return render_template('add_user.html', user=user_data)

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user_data = supabase.table('users').select('*').eq('id', user_id).execute().data[0]

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        role = request.form.get('role', 'user')  # Default role is 'user'

        try:
            supabase.table('users').update({
                'name': name,
                'email': email,
                'role': role
            }).eq('id', user_id).execute()

            flash('User updated successfully!', 'success')
            return redirect(url_for('admin_manage_users'))
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'danger')

    return render_template('edit_user.html', user=user_data)

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    try:
        supabase.table('users').delete().eq('id', user_id).execute()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Deletion failed: {str(e)}', 'danger')

    return redirect(url_for('admin_manage_users'))

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_manage_users():
    users_response = supabase.table('users').select('*').execute()
    users = users_response.data or []  # Handle None case
    return render_template('admin_users.html', users=users)

@app.route('/admin/create_user', methods=['POST'])
@admin_required
def create_user():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    role = request.form.get('role', 'user')

    if not email or not password or not name:
        flash('Email, Name, and Password are required!', 'danger')
        return redirect(url_for('add_user'))

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        supabase.table('users').insert({
            'email': email,
            'name': name,
            'password': hashed_password.decode('utf-8'),
            'role': role,
            'created_at': datetime.datetime.now().isoformat()
        }).execute()

        flash('User added successfully!', 'success')
        return redirect(url_for('admin_manage_users'))
    except Exception as e:
        flash(f'Failed to add user: {str(e)}', 'danger')
        return redirect(url_for('add_user'))
