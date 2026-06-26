import os
import logging
from app import create_app, db

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)

app = create_app()

with app.app_context():
    db.create_all()

    from flask_security.utils import hash_password
    from decouple import config

    user_datastore = app.security.datastore
    admin_email = config('ADMIN_EMAIL', default='admin@example.com')
    admin_pass  = config('ADMIN_PASSWORD', default='password123')

    if not user_datastore.find_user(email=admin_email):
        user_datastore.create_user(
            email=admin_email,
            username='admin',
            password=hash_password(admin_pass),
        )
        db.session.commit()
        logging.info('Created admin user: %s', admin_email)
