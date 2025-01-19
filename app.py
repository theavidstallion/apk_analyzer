from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_migrate import Migrate
from forms import SignupForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
from config import Config
import os
import json
from itsdangerous import URLSafeTimedSerializer
from androguard.core.apk import APK
from itsdangerous import SignatureExpired
from flask_dance.contrib.google import make_google_blueprint, google
from models import User, db
#from itsdangerous import TimedSerializer as Serializer
#from itsdangerous import URLSafeTimedSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer

# Initialize the serializer with your secret key
s = URLSafeTimedSerializer('your-secret-key')


# Initialize app
app = Flask(__name__)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your SMTP server
app.config['MAIL_PORT'] = 587  # Usually 587 for TLS or 465 for SSL
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'farooqj072@gmail.com'  # Your email address
app.config['MAIL_PASSWORD'] = 'rzdx ldtl uyzf sgvo'  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = 'farooqj072@gmail.com'  # Default sender for email
app.config['SECRET_KEY'] = 'dfnsa;dkjflksdjf;fkljasedsdw2343'

mail = Mail(app)

# Configure the app
app.config.from_object(Config)

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Import models here
from models import User, APKUpload  # Import your models explicitly

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize serializer for email verification and reset token
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Configure Google OAuth2
google_bp = make_google_blueprint(client_id='89689369343-r0fq61v09s5q3e3dbnajvm4abha0jhod.apps.googleusercontent.com',
                                   client_secret='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',
                                   redirect_to='google_login')
app.register_blueprint(google_bp, url_prefix='/google_login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('base.html')


# Routes for Signup, Login, Logout, and Forgot Password
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = SignupForm()
    if form.validate_on_submit():
        try:
            # Hash the password
            hashed_password = generate_password_hash(form.password.data, method='sha256')

            # Create the user with 'is_verified' set to False
            user = User(username=form.username.data, email=form.email.data, password=hashed_password, is_verified=False)
            db.session.add(user)
            db.session.commit()

            # Send the verification email
            send_verification_email(user.email)

            flash('Account created! Please verify your email.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {e}', 'danger')
    
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Extract form data
        email = form.email.data
        password = form.password.data

        # Debugging Logs
        print(f"Email submitted: {email}")
        print(f"Password submitted: {password}")

        # Fetch user from the database
        user = User.query.filter_by(email=email).first()

        # Check if the user exists and the password matches
        if user and check_password_hash(user.password, password):
            login_user(user)  # Log the user in using Flask-Login
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))  # Replace 'dashboard' with your actual route
        else:
            flash("Invalid email or password", "danger")

    # If GET or form validation fails, re-render the page with errors
    return render_template('login.html', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    uploads = APKUpload.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', uploads=uploads)


# APK Upload Route
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_apk():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in the request.', 'danger')
            return redirect(url_for('upload_apk'))

        file = request.files['file']

        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_apk'))

        if file:
            filename = file.filename
            upload_folder = 'uploads'
            os.makedirs(upload_folder, exist_ok=True)  # Create the uploads folder if it doesn't exist
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)

            try:
                # Analyze APK
                apk = APK(filepath)

                # Extract permissions
                permissions = apk.get_permissions() or []  # Fallback to an empty list if None

                # Extract metadata
                apk_metadata_raw = apk.get_files()  # Or use other APK methods for data

                # Debug: Print raw metadata for inspection
                print(f"DEBUG: Raw APK metadata: {apk_metadata_raw}")

                # Serialize the metadata to JSON-compatible format
                def serialize_metadata(data):
                    try:
                        if isinstance(data, dict):
                            return {k: serialize_metadata(v) for k, v in data.items()}
                        elif isinstance(data, list):
                            return [serialize_metadata(v) for v in data]
                        elif isinstance(data, (str, int, float, bool)) or data is None:
                            return data
                        else:
                            return str(data)  # Convert unsupported types to strings
                    except TypeError:
                        return None  # Ignore unserializable data

                apk_metadata = serialize_metadata(apk_metadata_raw)

                # Save the results in the database
                apk_upload = APKUpload(
                    user_id=current_user.id,
                    filename=filename,
                    apk_metadata=json.dumps(apk_metadata, default=str),  # Serialize metadata as JSON
                    permissions='\n'.join(permissions)
                )
                db.session.add(apk_upload)
                db.session.commit()

                # Show results on a webpage
                return render_template(
                    'upload_result.html',
                    filename=filename,
                    permissions=permissions,
                    apk_metadata=apk_metadata
                )
            except Exception as e:
                flash(f"Error analyzing APK: {str(e)}", 'danger')
                print(f"ERROR: {e}")
                return redirect(url_for('upload_apk'))

    return render_template('upload.html')

def send_verification_email(to_email):
    # Use the already initialized serializer 's'
    token = s.dumps(to_email, salt='email-confirm')

    # Create the verification link (pointing to the verify_email route)
    verification_link = url_for('verify_email', token=token, _external=True)

    # Compose the verification email message
    msg = Message('Please verify your email address',
                  recipients=[to_email])
    msg.body = f'Click the following link to verify your email: {verification_link}'

    try:
        # Send the email
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
        # You can also log the error or display a message if needed



@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        # Decrypt the token to get the user's email
        s = Serializer(app.config['SECRET_KEY'])
        email = s.loads(token, salt='email-confirm', max_age=3600)  # Token expires after 1 hour
    except SignatureExpired:
        flash('The verification link has expired.', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('login'))

    # Find the user by email
    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()
        flash('Your email has been verified. You can now log in.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('login'))



# Forgot and Reset Password Routes
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message('Reset Your Password', recipients=[user.email])
            msg.body = f'Please click the following link to reset your password: {reset_link}'
            msg.sender = app.config['MAIL_DEFAULT_SENDER']

            mail.send(msg)

            flash('Check your email for instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address.', 'danger')
    return render_template('forgot_password.html', form=form)


def generate_token(email):
    return s.dumps(email, salt='password-reset')

def decode_token(token, max_age=3600):
    try:
        # Decode the token, ensure it hasn't expired
        email = s.loads(token, salt='password-reset', max_age=max_age)
        return email
    except SignatureExpired:
        print("Token has expired!")
        return None
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None




@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode the token
        email = s.loads(token, salt='password-reset', max_age=3600)
        print(f"DEBUG: Email decoded from token: {email}")
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        flash('The password reset link is invalid or has expired.', 'danger')
        print(f"Error decoding token: {e}")
        return redirect(url_for('login'))

    # Fetch the user by email
    user = User.query.filter_by(email=email).first()
    print(f"DEBUG: User fetched from database: {user}")
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            # Hash the new password
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            print(f"DEBUG: New hashed password: {hashed_password}")

            # Remove the old password explicitly (optional but for clarity)
            print(f"DEBUG: Clearing old password: {user.password}")
            user.password = None
            db.session.commit()

            # Add the new password
            user.password = hashed_password
            db.session.commit()

            print(f"DEBUG: Updated password in database: {user.password}")
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while resetting your password.', 'danger')
            print(f"Error during password reset: {e}")

    # Render the password reset form
    return render_template('reset_with_token.html', form=form)




@app.route('/login/callback')
def google_login():
    if not google.authorized:
        return redirect(url_for('login'))  # Redirect to login page if authorization fails

    # Get the credentials from the Google OAuth provider
    google_token = google.get('/oauth2/v2/userinfo')  # Google Identity API (OAuth 2.0)

    if google_token.ok:
        # Get user data
        user_info = google_token.json()
        user_email = user_info['email']
        user_name = user_info['name']

        # Check if the user already exists in the database
        user = User.query.filter_by(email=user_email).first()

        if not user:
            # If the user does not exist, create a new user in the database
            user = User(email=user_email, name=user_name)
            db.session.add(user)
            db.session.commit()

        # Log in the user
        login_user(user)

        # Redirect to the dashboard or home page
        return redirect(url_for('dashboard'))
    else:
        flash('Failed to fetch Google user data', 'danger')
        return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)
