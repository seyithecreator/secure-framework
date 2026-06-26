import os
import json
import time
import logging
from collections import defaultdict

class LogWatcher:
    def __init__(self, log_dir='logs', block_file='config/blocked_ips.json', max_attempts=5, window=120, block_duration=3600):
        self.log_dir = log_dir
        self.block_file = block_file
        self.max_attempts = max_attempts
        self.window = window  # seconds
        self.block_duration = block_duration  # seconds
        
        self.attempts = defaultdict(list)
        self.blocked_ips = self.load_blocked_ips()

        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        if not os.path.exists(os.path.dirname(block_file)):
            os.makedirs(os.path.dirname(block_file))

    def load_blocked_ips(self):
        if os.path.exists(self.block_file):
            try:
                with open(self.block_file, 'r') as f:
                    data = json.load(f)
                    # Filter expired blocks
                    now = time.time()
                    return {ip: expiry for ip, expiry in data.items() if expiry > now}
            except json.JSONDecodeError:
                return {}
        return {}

    def save_blocked_ips(self):
        with open(self.block_file, 'w') as f:
            json.dump(self.blocked_ips, f)

    def log_failed_attempt(self, ip, service):
        """Logs a failed login attempt and checks if the IP should be blocked."""
        now = time.time()
        self.attempts[ip].append(now)
        
        # Clean up old attempts for this IP
        self.attempts[ip] = [t for t in self.attempts[ip] if now - t < self.window]
        
        if len(self.attempts[ip]) >= self.max_attempts:
            self.block_ip(ip, f"Too many failed attempts on {service}")
            return True
        return False

    def block_ip(self, ip, reason):
        expiry = time.time() + self.block_duration
        self.blocked_ips[ip] = expiry
        self.save_blocked_ips()
        logging.warning(f"BLOCKED IP: {ip} - Reason: {reason}")

    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self.save_blocked_ips()
            logging.info(f"UNBLOCKED IP: {ip}")

    def is_blocked(self, ip):
        now = time.time()
        if ip in self.blocked_ips:
            if self.blocked_ips[ip] > now:
                return True
            else:
                self.unblock_ip(ip)
        return False

    def get_blocked_list(self):
        """Returns list of blocked IPs with expiry info."""
        now = time.time()
        # Clean up expired ones before returning
        self.blocked_ips = {ip: expiry for ip, expiry in self.blocked_ips.items() if expiry > now}
        return self.blocked_ips

if __name__ == "__main__":
    watcher = LogWatcher(log_dir='../logs', block_file='../config/blocked_ips.json')
    test_ip = "192.168.1.100"
    for i in range(5):
        blocked = watcher.log_failed_attempt(test_ip, "SFTP")
        print(f"Attempt {i+1}: Blocked? {blocked}")
    print(f"Is {test_ip} blocked? {watcher.is_blocked(test_ip)}")
