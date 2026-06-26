import os
from flask import Blueprint, render_template, request, send_from_directory, send_file, redirect, flash, current_app, url_for
from flask_security import login_required, current_user
from werkzeug.utils import secure_filename
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import io

files_bp = Blueprint('files', __name__, url_prefix='/files')

def get_fernet():
    # Derive a secure 32-byte key from the Flask app's SECRET_KEY
    secret = current_app.config['SECRET_KEY'].encode()
    salt = b'secure_framework_file_salt_v1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret))
    return Fernet(key)

def get_upload_path():
    path = os.path.join(current_app.root_path, '..', 'files_store')
    if not os.path.exists(path):
        os.makedirs(path)
    return os.path.abspath(path)

UPLOAD_FOLDER = 'files_store'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'tar.gz'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@files_bp.route('/')
@login_required
def list_files():
    user_dir = os.path.join(get_upload_path(), current_user.email)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
        
    files = os.listdir(user_dir)
    return render_template('files.html', files=files)

@files_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('files.list_files'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('files.list_files'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_dir = os.path.join(get_upload_path(), current_user.email)
        
        # Read the raw file stream and encrypt it in memory
        raw_data = file.read()
        f = get_fernet()
        encrypted_data = f.encrypt(raw_data)
        
        # Save the encrypted cipher text to the filesystem
        with open(os.path.join(user_dir, filename), 'wb') as enc_file:
            enc_file.write(encrypted_data)
            
        flash(f'File {filename} encrypted and stored successfully!', 'success')
        return redirect(url_for('files.list_files'))
    else:
        flash('Invalid file type', 'error')
        return redirect(url_for('files.list_files'))

@files_bp.route('/download/<filename>')
@login_required
def download_file(filename):
    user_dir = os.path.join(get_upload_path(), current_user.email)
    file_path = os.path.join(user_dir, secure_filename(filename))
    
    if not os.path.exists(file_path):
        flash('File not found.', 'error')
        return redirect(url_for('files.list_files'))
        
    try:
        # Read encrypted data from disk
        with open(file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()
            
        # Decrypt back to original file content
        f = get_fernet()
        decrypted_data = f.decrypt(encrypted_data)
        
        # Send to user securely without saving decrypted version to disk
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        flash('Failed to decrypt file. The encryption key may have changed or the file is corrupted.', 'error')
        return redirect(url_for('files.list_files'))

@files_bp.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    user_dir = os.path.join(get_upload_path(), current_user.email)
    file_path = os.path.join(user_dir, secure_filename(filename))
    
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'File {filename} deleted securely.', 'success')
    else:
        flash('File not found.', 'error')
        
    return redirect(url_for('files.list_files'))

@files_bp.route('/edit/<filename>', methods=['GET'])
@login_required
def edit_file_view(filename):
    user_dir = os.path.join(get_upload_path(), current_user.email)
    file_path = os.path.join(user_dir, secure_filename(filename))
    
    if not os.path.exists(file_path):
        flash('File not found.', 'error')
        return redirect(url_for('files.list_files'))
        
    if not filename.lower().endswith('.txt'):
        flash('Only text files can be edited in the browser.', 'warning')
        return redirect(url_for('files.list_files'))
        
    try:
        # Decrypt for viewing
        with open(file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()
            
        f = get_fernet()
        decrypted_text = f.decrypt(encrypted_data).decode('utf-8', errors='ignore')
        
        return render_template('edit_file.html', filename=filename, content=decrypted_text)
    except Exception as e:
        flash('Failed to decrypt and open file.', 'error')
        return redirect(url_for('files.list_files'))

@files_bp.route('/edit/<filename>', methods=['POST'])
@login_required
def edit_file_save(filename):
    user_dir = os.path.join(get_upload_path(), current_user.email)
    file_path = os.path.join(user_dir, secure_filename(filename))
    
    if not os.path.exists(file_path):
        flash('File not found.', 'error')
        return redirect(url_for('files.list_files'))
        
    if not filename.lower().endswith('.txt'):
        flash('Only text files can be edited in the browser.', 'warning')
        return redirect(url_for('files.list_files'))
        
    new_content = request.form.get('content', '')
    
    try:
        # Re-encrypt the new text before saving to disk
        f = get_fernet()
        encrypted_data = f.encrypt(new_content.encode('utf-8'))
        
        with open(file_path, 'wb') as enc_file:
            enc_file.write(encrypted_data)
            
        flash(f'File {filename} updated securely.', 'success')
    except Exception as e:
        flash('Failed to encrypt and save file.', 'error')
        
    return redirect(url_for('files.list_files'))

