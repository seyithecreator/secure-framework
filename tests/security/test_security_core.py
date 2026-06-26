import os
import pytest
from security.tls_manager import TLSManager
from security.log_watcher import LogWatcher
from ftp_server.user_manager import FTPUserManager

def test_tls_generation():
    manager = TLSManager(cert_dir='tests/certs')
    cert, key = manager.generate_self_signed_cert()
    assert os.path.exists(cert)
    assert os.path.exists(key)
    status, expiry = manager.get_cert_status()
    assert status == "Valid"
    # Cleanup
    os.remove(cert)
    os.remove(key)
    os.removedirs('tests/certs')

def test_password_hashing():
    um = FTPUserManager(db_path='tests/test_users.db')
    um.add_user('test', 'password123', 'tests/home')
    auth = um.authenticate_user('test', 'password123')
    assert auth is not None
    assert auth['username'] == 'test'
    # Cleanup
    os.remove('tests/test_users.db')
    os.removedirs('tests/home')

def test_ip_blocking():
    watcher = LogWatcher(block_file='tests/test_blocks.json', max_attempts=3)
    ip = "1.2.3.4"
    watcher.log_failed_attempt(ip, "test")
    watcher.log_failed_attempt(ip, "test")
    assert watcher.is_blocked(ip) is False
    watcher.log_failed_attempt(ip, "test")
    assert watcher.is_blocked(ip) is True
    # Cleanup
    os.remove('tests/test_blocks.json')
