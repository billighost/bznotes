from flask import Flask
from config import Config
from extensions import db, migrate
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from waitress import serve
# ✅ Initialize Flask app
app = Flask(__name__)

# ✅ Configure Database (Ensure This Exists)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Update as needed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✅ Initialize Database
db = SQLAlchemy(app)

# ✅ Initialize Socket.IO
socketio = SocketIO(app)

# ✅ Import routes at the bottom to avoid circular imports
from run import *

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)  # Load configuration

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'  # Define login route

    return app
