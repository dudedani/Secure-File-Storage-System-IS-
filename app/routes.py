from flask import send_file
from app.utils import analyze_file
from flask import Blueprint, render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from app.models import User, File
from app.forms import RegistrationForm, LoginForm, FileUploadForm
from app.utils import encrypt_file, decrypt_file, analyze_file
from flask_mail import Message
import io
from app import bcrypt
from app.malicious_file_detection import analyze_file
from werkzeug.utils import secure_filename
import os


UPLOAD_FOLDER = os.path.join(os.getcwd(), "files")  # Ensure the 'files' directory exists
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'jpg', 'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS






# Create a Blueprint for routes
routes = Blueprint('routes', __name__)

# Home route
@routes.route("/")
@login_required
def home():
    return render_template('dashboard.html')

# Registration route
@routes.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))  # Redirect to home if already logged in

    form = RegistrationForm()
    if form.validate_on_submit():
        from app import bcrypt, db  # Import bcrypt and db locally
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('routes.login'))  # Redirect to login page after successful registration

    return render_template('register.html', form=form)

#Login Route
@routes.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))  # Redirect to home if already logged in

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()  # Get user by email
        if user and bcrypt.check_password_hash(user.password, form.password.data):  # Check password hash
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('routes.home'))  # Redirect to home page
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

# Logout route
@routes.route("/logout")
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.login'))

#File upload route
# @routes.route("/upload", methods=['GET', 'POST'])
# @login_required
# def upload_file():
#     form = FileUploadForm()
#     if form.validate_on_submit():
#         file = form.file.data
#         file_data = file.read()  # Read the file content
#         # Debug: Check the uploaded file's details
#         print(f"Uploaded file: {file.filename}")
#         print(f"File size: {len(file_data)} bytes")
#         print(f"First 100 bytes of file: {file_data[:100]}")
#         try:
#             # Analyze the file for maliciousness
#             is_malicious = analyze_file(file_data)
#             print(f"Malicious analysis result: {is_malicious}")
#         except Exception as e:
#             print(f"Error during malicious file detection: {e}")
#             flash('An error occurred during file analysis. Please try again.', 'danger')
#             return redirect(url_for('routes.upload_file'))
        
#         if is_malicious:
#             flash('The uploaded file is potentially malicious and cannot be saved.', 'danger')
#             return redirect(url_for('routes.upload_file'))

#         # Proceed with file encryption or saving
#         flash('File uploaded successfully.', 'success')
#         return redirect(url_for('routes.files'))

#     return render_template('upload.html', form=form)


@routes.route("/upload", methods=['GET', 'POST'])
@login_required
def upload_file():
    form = FileUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file:
            filename = file.filename
            file_data = file.read()  # Read the file content
            
            # Debug: Check the uploaded file's details
            print(f"Uploaded file: {filename}")
            print(f"File size: {len(file_data)} bytes")
            print(f"First 100 bytes of file: {file_data[:100]}")

            # Analyze the file for maliciousness
            try:
                is_malicious = analyze_file(file_data)
                print(f"Malicious analysis result: {is_malicious}")
            except Exception as e:
                print(f"Error during malicious file detection: {e}")
                flash('An error occurred during file analysis. Please try again.', 'danger')
                return redirect(url_for('routes.upload_file'))
            
            if is_malicious:
                flash('The uploaded file is potentially malicious and cannot be saved.', 'danger')
                return redirect(url_for('routes.upload_file'))

            # Encrypt file data
            try:
                encrypted_file, key = encrypt_file(file_data)
                print(f"File encrypted successfully: {filename}")
            except Exception as e:
                print(f"Error during file encryption: {e}")
                flash('An error occurred during file encryption. Please try again.', 'danger')
                return redirect(url_for('routes.upload_file'))

            # Save file to database
            from app import db
            new_file = File(
                filename=filename,
                encrypted_file=encrypted_file,
                key=key,
                user_id=current_user.id
            )
            try:
                db.session.add(new_file)
                db.session.commit()
                print(f"File saved to database: {filename}")
            except Exception as e:
                print(f"Error saving file to database: {e}")
                flash('An error occurred while saving the file. Please try again.', 'danger')
                return redirect(url_for('routes.upload_file'))

            # Success message
            flash('File uploaded successfully.', 'success')
            return redirect(url_for('routes.files'))

    return render_template('upload.html', form=form)




@routes.route("/files")
@login_required
def files():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    print(f"DEBUG: Retrieved Files for User {current_user.id}: {[file.filename for file in user_files]}")
    print(f"DEBUG: Number of files retrieved: {len(user_files)}")
    return render_template('files.html', files=user_files)



# Route for decrypting and downloading a file
@routes.route("/decrypt/<int:file_id>")
@login_required
def decrypt_file_route(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:  # Check if the user is the owner of the file
        flash('You do not have permission to decrypt this file.', 'danger')
        return redirect(url_for('routes.files'))

    decrypted_data = decrypt_file(file.encrypted_file, file.key)  # Use the correct key
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file.filename
    )


# Utility function to send an email alert for malicious files
def send_alert(user_email):
    from app import mail  # Import mail locally
    msg = Message('Malicious File Detected', sender='l215169@gmail.com', recipients=[user_email])
    msg.body = 'A file you uploaded has been flagged as malicious. Please take appropriate action.'
    mail.send(msg)



# Route for deleting a file
@routes.route("/delete/<int:file_id>", methods=['POST'])
@login_required
def delete_file(file_id):
    # Fetch the file from the database
    file = File.query.get_or_404(file_id)
    
    # Ensure the file belongs to the current user
    if file.user_id != current_user.id:
        flash('You do not have permission to delete this file.', 'danger')
        return redirect(url_for('routes.files'))
    
    try:
        # Remove the file from the database
        from app import db  # Import db locally
        db.session.delete(file)
        db.session.commit()
        flash('File deleted successfully.', 'success')
    except Exception as e:
        print(f"Error deleting file: {e}")
        flash('An error occurred while deleting the file. Please try again.', 'danger')
    
    return redirect(url_for('routes.files'))
