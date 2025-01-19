import os

class Config:
    SECRET_KEY = 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db' 

    # Email Settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'farooqj072@gmail.com'  # Enter your email here
    MAIL_PASSWORD = 'rzdx ldtl uyzf sgvo'  # Enter your password here

    # Google OAuth Config (if you want to use OAuth)
    GOOGLE_CLIENT_ID = '661060623580-ahmroarrqmlhd6dj6009160a6b3nscq7.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'
    GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'
