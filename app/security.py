from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

csp = {
    'default-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com',
    ],
    'script-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
    ],
    'font-src': [
        '\'self\'',
        'https://fonts.gstatic.com',
    ]
}

def init_security(app):
    csrf.init_app(app)
    limiter.init_app(app)
    
    # Talisman handles HSTS, Content Security Policy, etc.
    Talisman(
        app,
        content_security_policy=csp,
        force_https=False, # Set to True in production with real SSL
        session_cookie_secure=True,
        session_cookie_http_only=True,
        strict_transport_security=True,
        frame_options='DENY'
    )
