import os
import hashlib
import json
import logging

class ConfigAuditor:
    def __init__(self, config_files=None, baseline_file='config/baseline.json'):
        self.config_files = config_files or [
            'config/framework_config.py',
            'config/ftp_settings.json',
            '.env'
        ]
        self.baseline_file = baseline_file
        
        if not os.path.exists(os.path.dirname(baseline_file)):
            os.makedirs(os.path.dirname(baseline_file))

    def calculate_hash(self, filepath):
        if not os.path.exists(filepath):
            return None
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def generate_baseline(self):
        baseline = {}
        for filepath in self.config_files:
            file_hash = self.calculate_hash(filepath)
            if file_hash:
                baseline[filepath] = file_hash
            else:
                logging.warning(f"File not found for baseline: {filepath}")
        
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=4)
        return baseline

    def run_audit(self):
        if not os.path.exists(self.baseline_file):
            return {"status": "error", "message": "Baseline not found. Run baseline generation first."}
        
        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)
            
        results = []
        overall_pass = True
        
        for filepath, expected_hash in baseline.items():
            current_hash = self.calculate_hash(filepath)
            if current_hash is None:
                results.append({"file": filepath, "status": "FAIL", "reason": "File missing"})
                overall_pass = False
            elif current_hash != expected_hash:
                results.append({"file": filepath, "status": "FAIL", "reason": "Hash mismatch (drift detected)"})
                overall_pass = False
            else:
                results.append({"file": filepath, "status": "PASS", "reason": "Matches baseline"})
                
        return {
            "status": "success",
            "overall_pass": overall_pass,
            "results": results
        }

if __name__ == "__main__":
    # Test
    auditor = ConfigAuditor(baseline_file='../config/baseline.json')
    # Create dummy files for testing
    os.makedirs('../config', exist_ok=True)
    with open('../config/ftp_settings.json', 'w') as f: f.write("{}")
    
    print("Generating baseline...")
    auditor.generate_baseline()
    
    print("Running audit...")
    print(json.dumps(auditor.run_audit(), indent=4))
    
    print("Modifying file...")
    with open('../config/ftp_settings.json', 'w') as f: f.write("{\"modified\": true}")
    
    print("Running audit again...")
    print(json.dumps(auditor.run_audit(), indent=4))
