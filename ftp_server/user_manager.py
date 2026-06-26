import sqlite3
import hashlib
import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class FTPUserManager:
    def __init__(self, db_path='config/users.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
            
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS ftp_users
                     (username TEXT PRIMARY KEY, 
                      password_hash TEXT, 
                      salt TEXT,
                      home_dir TEXT, 
                      role TEXT,
                      permissions TEXT)''')
        conn.commit()
        conn.close()

    def _hash_password(self, password, salt=None):
        if salt is None:
            salt = secrets.token_bytes(16)
        else:
            salt = bytes.fromhex(salt)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key.hex(), salt.hex()

    def add_user(self, username, password, home_dir, role='user', permissions='elradfmwMT'):
        """
        Permissions (pyftpdlib style):
        e = change directory
        l = list files
        r = retrieve file
        a = append data
        d = delete file
        f = rename file
        m = make directory
        w = write file
        M = mode (chmod)
        T = time (utime)
        """
        password_hash, salt = self._hash_password(password)
        
        # Ensure home_dir exists
        if not os.path.exists(home_dir):
            os.makedirs(home_dir)
            
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO ftp_users VALUES (?, ?, ?, ?, ?, ?)",
                      (username, password_hash, salt, home_dir, role, permissions))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def authenticate_user(self, username, password):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT password_hash, salt, home_dir, permissions FROM ftp_users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row:
            stored_hash, salt, home_dir, permissions = row
            target_hash, _ = self._hash_password(password, salt)
            if target_hash == stored_hash:
                return {"username": username, "home_dir": home_dir, "permissions": permissions}
        return None

    def get_all_users(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT username, home_dir, role FROM ftp_users")
        users = c.fetchall()
        conn.close()
        return [{"username": u[0], "home_dir": u[1], "role": u[2]} for u in users]

    def delete_user(self, username):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM ftp_users WHERE username=?", (username,))
        conn.commit()
        conn.close()

if __name__ == "__main__":
    mgr = FTPUserManager('../config/users.db')
    mgr.add_user('testuser', 'testpass', '../files/testuser')
    auth = mgr.authenticate_user('testuser', 'testpass')
    print(f"Auth success: {auth}")
