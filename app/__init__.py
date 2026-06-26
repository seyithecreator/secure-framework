import os
from flask import Flask, render_template
from flask_security import Security, SQLAlchemyUserDatastore, login_required
from werkzeug.middleware.proxy_fix import ProxyFix
from app.models import db, User, Role
from app.security import init_security
from decouple import config

__all__ = ['create_app', 'db']

def _get_db_url():
    url = config('DATABASE_URL', default='sqlite:///secure_framework.db')
    # Render (and older Heroku) provides postgres:// but SQLAlchemy requires postgresql://
    if url.startswith('postgres://'):
        url = 'postgresql://' + url[len('postgres://'):]
    return url

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    # Trust one proxy hop (Render's load balancer)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Load configuration from environment variables
    app.config.from_mapping(
        SECRET_KEY=config('SECRET_KEY', default='dev-secret-key'),
        SQLALCHEMY_DATABASE_URI=_get_db_url(),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        TEMPLATES_AUTO_RELOAD=True,
        SECURITY_PASSWORD_SALT=config('SECURITY_PASSWORD_SALT', default='salt-for-security'),
        SECURITY_REGISTERABLE=True,
        SECURITY_SEND_REGISTER_EMAIL=False,
        SECURITY_POST_LOGIN_VIEW='/dashboard',
        SECURITY_POST_LOGOUT_VIEW='/login',
        SECURITY_RECOVERABLE=False,
        SECURITY_CHANGEABLE=True,
        SECURITY_FLASH_MESSAGES=True,
        SECURITY_USER_IDENTITY_ATTRIBUTES=[
            {"email": {"case_insensitive": True}},
        ],
        SECURITY_USERNAME_ENABLE=True,
        SECURITY_PASSWORD_HASH="argon2",
        SECURITY_MSG_INVALID_PASSWORD=("Invalid email or password.", "error"),
        SECURITY_MSG_USER_DOES_NOT_EXIST=("Invalid email or password.", "error"),
    )
    
    if test_config:
        app.config.from_mapping(test_config)

    # Initialize extensions
    db.init_app(app)
    init_security(app)
    
    # Register Blueprints
    from app.files.routes import files_bp
    app.register_blueprint(files_bp)

    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, user_datastore)

    with app.app_context():
        db.create_all()

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/settings')
    @login_required
    def settings():
        return render_template('settings.html')

    return app
