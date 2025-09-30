from flask import Flask
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .config import Config
from .models.database import db
import os

# Allow HTTP for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

def create_app(config_class=Config):
    # Flask app'i root klasöründen başlat (templates ve static için)
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Bu sayfayı görüntülemek için giriş yapmalısınız.'
    login_manager.login_message_category = 'info'
    
    # Initialize Rate limiter
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=['200 per day', '50 per hour'],
        storage_uri='memory://'
    )
    
    # User loader function
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        try:
            return User.query.get(int(user_id))
        except Exception as e:
            print(f"User loading error: {e}")
            return None
    
    # Register blueprints
    from .routes import auth_bp, main_bp, words_bp, analysis_bp, rooms_bp, settings_bp, sentences_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(words_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(rooms_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(sentences_bp)
    
    # Create database tables
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    return app
