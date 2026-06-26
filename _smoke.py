"""Smoke test: verify required imports and Flask app factory."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Step 1: import all the packages we'll need
mods = ['flask', 'flask_security', 'flask_talisman', 'flask_limiter',
        'flask_wtf', 'cryptography', 'paramiko', 'pyftpdlib',
        'decouple', 'docx', 'marshmallow', 'bleach']
missing = []
for m in mods:
    try:
        __import__(m)
    except ImportError as e:
        missing.append((m, str(e)))
if missing:
    print('MISSING:', missing)
else:
    print('all deps ok')

# Step 2: import the Flask factory
try:
    from app import create_app, db
    app = create_app()
    print('flask app created ok; rules:')
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        print(' ', rule.rule, '->', rule.endpoint)
except Exception as e:
    import traceback
    traceback.print_exc()
