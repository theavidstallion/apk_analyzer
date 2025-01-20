import os

class Config:
    SECRET_KEY = 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db' 

    # Email Settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'raventechgeeks@gmail.com'  # Enter your email here
    MAIL_PASSWORD = 'rzdx ldtl uyzf sgvo'  # Enter your password here

    # Google OAuth Config (if you want to use OAuth)
    GOOGLE_CLIENT_ID = '89689369343-r0fq61v09s5q3e3dbnajvm4abha0jhod.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'
    GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'
