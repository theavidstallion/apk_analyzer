from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=True)  # Optional for Google OAuth
    is_verified = db.Column(db.Boolean, default=False)  # Email verification flag

    def __repr__(self):
        return f'<User {self.username}>'

class APKUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(150), nullable=False)
    apk_metadata = db.Column(db.Text, nullable=True)  # Renamed from 'metadata' to 'apk_metadata'
    permissions = db.Column(db.Text, nullable=True)
    date_uploaded = db.Column(db.DateTime, default=db.func.now())
