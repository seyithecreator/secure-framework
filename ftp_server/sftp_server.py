import os
import time
import socket
import threading
import logging
import paramiko
from ftp_server.user_manager import FTPUserManager
from security.log_watcher import LogWatcher

class SFTPServerInterface(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        self.server = server
        super().__init__(server, *args, **kwargs)

    def list_folder(self, path):
        # Implementation of chrooted file operations
        full_path = self._realpath(path)
        try:
            out = []
            for name in os.listdir(full_path):
                attr = paramiko.SFTPAttributes.from_stat(os.stat(os.path.join(full_path, name)))
                attr.filename = name
                out.append(attr)
            return out
        except OSError:
            return paramiko.SFTP_FAILURE

    def stat(self, path):
        full_path = self._realpath(path)
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(full_path))
        except OSError:
            return paramiko.SFTP_FAILURE

    def _realpath(self, path):
        # Resolve and confine to home_dir to prevent path traversal
        resolved = os.path.realpath(os.path.join(self.server.home_dir, path.lstrip('/')))
        if not resolved.startswith(os.path.realpath(self.server.home_dir)):
            return self.server.home_dir
        return resolved

class SSHServer(paramiko.ServerInterface):
    def __init__(self, user_manager, log_watcher):
        self.user_manager = user_manager
        self.log_watcher = log_watcher
        self.event = threading.Event()
        self.home_dir = None
        self.authenticated_user = None

    def check_auth_password(self, username, password):
        user_data = self.user_manager.authenticate_user(username, password)
        if user_data:
            self.authenticated_user = username
            self.home_dir = user_data['home_dir']
            logging.info(f"SFTP Login successful for user {username}")
            return paramiko.AUTH_SUCCESSFUL
        
        logging.warning(f"SFTP Login failed for user {username}")
        # Note: IP blocking logic would need to be handled at the socket connection level
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, bh_chan, name):
        self.event.set()
        if name == 'sftp':
            return True
        return False

class SFTPServerModule:
    def __init__(self, host='0.0.0.0', port=2222, user_manager=None, log_watcher=None, host_key_path='config/sftp_host.key'):
        self.host = host
        self.port = port
        self.user_manager = user_manager
        self.log_watcher = log_watcher
        self.host_key_path = host_key_path
        
        if not os.path.exists(host_key_path):
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(host_key_path)
        
        self.host_key = paramiko.RSAKey(filename=host_key_path)
        self.is_running = False

    def handle_client(self, client_sock, addr):
        logging.info(f"SFTP Connection from {addr[0]}")
        
        if self.log_watcher.is_blocked(addr[0]):
            logging.warning(f"SFTP rejected blocked IP: {addr[0]}")
            client_sock.close()
            return

        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self.host_key)
            transport.set_subsystem_handler('sftp', paramiko.SFTPServer, SFTPServerInterface)
            
            server = SSHServer(self.user_manager, self.log_watcher)
            transport.start_server(server=server)
            
            channel = transport.accept(20)
            if channel is None:
                return
            
            server.event.wait(10)
            if not server.event.is_set():
                transport.close()
                return

            while transport.is_active():
                time.sleep(1)
        except Exception as e:
            logging.error(f"SFTP error: {e}")
        finally:
            transport.close()

    def start(self):
        self.is_running = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(100)
        
        logging.info(f"Starting SFTP server on {self.host}:{self.port}")
        
        while self.is_running:
            try:
                client_sock, addr = server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()
            except Exception as e:
                if self.is_running:
                    logging.error(f"SFTP accept error: {e}")

    def stop(self):
        self.is_running = False
        logging.info("SFTP server stopping...")

if __name__ == "__main__":
    import time
    logging.basicConfig(level=logging.INFO)
    um = FTPUserManager('../config/users.db')
    lw = LogWatcher(log_dir='../logs', block_file='../config/blocked_ips.json')
    
    sftp = SFTPServerModule(port=2222, user_manager=um, log_watcher=lw, host_key_path='../config/sftp_host.key')
    try:
        sftp.start()
    except KeyboardInterrupt:
        sftp.stop()
