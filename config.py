import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Flask Configuration Settings"""

    # ✅ Security settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secure-key-@zK9!pQ3rT')

    # ✅ Database configuration: Use DATABASE_URL if provided, otherwise fallback to SQLite
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///bz_notes.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
     
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
    
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "bb2010ng@gmail.com")  # Default fallback
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = ("B'z Notes Pro", MAIL_USERNAME)  

    # ✅ Session Management
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # ✅ CSRF Protection
    CSRF_ENABLED = True

    # ✅ Content Security Policy settings
    CSP = {
        'default-src': "'self'",
        'script-src': ["'self'", "https://cdnjs.cloudflare.com"],
        'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        'font-src': ["'self'", "https://fonts.gstatic.com"]
    }
