import os
import logging
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer
from ftp_server.user_manager import FTPUserManager
from security.tls_manager import TLSManager
from security.log_watcher import LogWatcher

class SecureFTPHandler(TLS_FTPHandler):
    def on_login_failed(self, username, password):
        ip = self.remote_ip
        logging.warning(f"FTPS Login failed for user {username} from {ip}")
        if hasattr(self.server, 'log_watcher'):
            self.server.log_watcher.log_failed_attempt(ip, "FTPS")
        super().on_login_failed(username, password)

    def on_login(self, username):
        logging.info(f"FTPS Login successful for user {username} from {self.remote_ip}")
        super().on_login(username)

class CustomAuthorizer(DummyAuthorizer):
    def __init__(self, user_manager):
        super().__init__()
        self.user_manager = user_manager

    def validate_authentication(self, username, password, handler):
        user_data = self.user_manager.authenticate_user(username, password)
        if not user_data:
            raise AuthenticationFailed("Invalid username or password.")
        
        # Dynamically add user if authenticated
        if not self.has_user(username):
            self.add_user(username, "", user_data['home_dir'], perm=user_data['permissions'])
        
        return True

class FTPSServerModule:
    def __init__(self, host='0.0.0.0', port=990, user_manager=None, log_watcher=None, cert_manager=None):
        self.host = host
        self.port = port
        self.user_manager = user_manager
        self.log_watcher = log_watcher
        self.cert_manager = cert_manager or TLSManager()
        
        self.server = None

    def start(self):
        authorizer = CustomAuthorizer(self.user_manager)
        
        handler = SecureFTPHandler
        handler.authorizer = authorizer
        
        # Security hardening
        handler.certfile, handler.keyfile = self.cert_manager.get_cert_status()[0] == "Valid" and \
                                            (self.cert_manager.cert_path, self.cert_manager.key_path) or \
                                            self.cert_manager.generate_self_signed_cert()
                                            
        handler.tls_control_required = True
        handler.tls_data_required = True
        handler.banner = "Secure Framework FTPS Server Ready."
        handler.passive_ports = range(60000, 65535)
        
        self.server = FTPServer((self.host, self.port), handler)
        self.server.log_watcher = self.log_watcher # Attach log watcher to server instance
        
        logging.info(f"Starting FTPS server on {self.host}:{self.port}")
        self.server.serve_forever()

    def stop(self):
        if self.server:
            self.server.close_all()
            logging.info("FTPS server stopped.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    um = FTPUserManager('../config/users.db')
    lw = LogWatcher(log_dir='../logs', block_file='../config/blocked_ips.json')
    cm = TLSManager(cert_dir='../certs')
    
    ftps = FTPSServerModule(port=2121, user_manager=um, log_watcher=lw, cert_manager=cm)
    try:
        ftps.start()
    except KeyboardInterrupt:
        ftps.stop()
