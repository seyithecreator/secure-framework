import os
import threading
import logging
import time
from decouple import config
from app import create_app, db
from ftp_server.ftps_server import FTPSServerModule
from ftp_server.sftp_server import SFTPServerModule
from ftp_server.user_manager import FTPUserManager
from security.tls_manager import TLSManager
from security.log_watcher import LogWatcher
from security.config_auditor import ConfigAuditor
from gui.main_window import MainApplication

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/framework.log"),
        logging.StreamHandler()
    ]
)

class SecurityFramework:
    def __init__(self):
        self.tls_manager = TLSManager()
        self.log_watcher = LogWatcher()
        self.user_manager = FTPUserManager()
        self.auditor = ConfigAuditor()
        
        # Ensure directories exist
        if not os.path.exists('logs'): os.makedirs('logs')
        if not os.path.exists('files_store'): os.makedirs('files_store')
        
        # Initialize Flask
        self.flask_app = create_app()
        
        # Initialize FTP Servers
        self.ftps_server = FTPSServerModule(
            user_manager=self.user_manager, 
            log_watcher=self.log_watcher,
            cert_manager=self.tls_manager
        )
        self.sftp_server = SFTPServerModule(
            user_manager=self.user_manager,
            log_watcher=self.log_watcher
        )

    def run_setup(self):
        """Initial setup wizard logic."""
        if not os.path.exists('config/baseline.json'):
            logging.info("First run detected. Generating baseline and initial certs.")
            self.tls_manager.generate_self_signed_cert()
            self.auditor.generate_baseline()
            
            # Create default admin user if not exists
            admin_email = config('ADMIN_EMAIL', default='admin@example.com')
            admin_pass = config('ADMIN_PASSWORD', default='password123')
            
            # FTP Admin
            self.user_manager.add_user(admin_email, admin_pass, 'files_store/admin', role='admin')
            
            # Web Admin (Flask-Security)
            with self.flask_app.app_context():
                from flask_security.utils import hash_password
                user_datastore = self.flask_app.security.datastore
                if not user_datastore.find_user(email=admin_email):
                    user_datastore.create_user(
                        email=admin_email,
                        username='admin',
                        password=hash_password(admin_pass)
                    )
                    db.session.commit()
                    logging.info(f"Created web admin user: {admin_email}")

    def start_gui(self):
        app = MainApplication()
        # Pass the framework instances to the GUI
        app.tls_manager = self.tls_manager
        app.log_watcher = self.log_watcher
        app.user_manager = self.user_manager
        app.auditor = self.auditor
        
        # Overwrite the toggle_server method to actually start things
        framework = self
        original_toggle = app.toggle_server
        
        def new_toggle(key, start):
            if start:
                if key == "web":
                    t = threading.Thread(target=lambda: framework.flask_app.run(
                        host='0.0.0.0', 
                        port=config('WEB_PORT', default=5443, cast=int),
                        ssl_context=(framework.tls_manager.cert_path, framework.tls_manager.key_path),
                        use_reloader=False
                    ), daemon=True)
                    t.start()
                    framework.flask_app_thread = t
                elif key == "ftps":
                    t = threading.Thread(target=framework.ftps_server.start, daemon=True)
                    t.start()
                elif key == "sftp":
                    t = threading.Thread(target=framework.sftp_server.start, daemon=True)
                    t.start()
            else:
                if key == "ftps": framework.ftps_server.stop()
                elif key == "sftp": framework.sftp_server.stop()
                # Flask is harder to stop cleanly in dev mode, usually just let it go
            
            original_toggle(key, start)

        app.toggle_server = new_toggle
        app.mainloop()

if __name__ == "__main__":
    framework = SecurityFramework()
    framework.run_setup()
    framework.start_gui()
