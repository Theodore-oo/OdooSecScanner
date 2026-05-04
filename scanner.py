import os
import zipfile
import tempfile
import re
from typing import List, Dict, Any

class Scanner:
    def __init__(self):
        self.rules = [
            {
                "id": "A01:2025",
                "name": "Broken Access Control",
                "description": "Checks for excessive permissions, sudo() misuse, or missing ir.model.access.csv.",
                "patterns": [
                    (r'\.sudo\(\)', "Usage of sudo() detected. Ensure it is strictly necessary and input is sanitized."),
                    (r'groups\s*=\s*[\'"]base\.group_erp_manager[\'"]', "High privilege group assigned.")
                ],
                "file_types": [".py", ".xml"]
            },
            {
                "id": "A03:2025",
                "name": "Software Supply Chain Failures",
                "description": "Checks for external dependencies which may introduce vulnerabilities.",
                "patterns": [
                    (r'[\'"]external_dependencies[\'"]\s*:\s*\{', "Module has external dependencies. Ensure they are secure and up-to-date.")
                ],
                "file_types": [".py"]
            },
            {
                "id": "A04:2025",
                "name": "Cryptographic Failures",
                "description": "Use of weak hashing algorithms or hardcoded secrets.",
                "patterns": [
                    (r'hashlib\.md5\(', "Use of weak hashing algorithm MD5."),
                    (r'hashlib\.sha1\(', "Use of weak hashing algorithm SHA1."),
                    (r'(?i)password\s*=\s*[\'"][^\'"]+[\'"]', "Potential hardcoded password found.")
                ],
                "file_types": [".py", ".xml"]
            },
            {
                "id": "A05:2025",
                "name": "Injection",
                "description": "SQL injection via cr.execute or eval() misuse.",
                "patterns": [
                    (r'cr\.execute\s*\([^,]+%', "Potential SQL Injection: String formatting used in cr.execute()."),
                    (r'cr\.execute\s*\([^,]+\.format\(', "Potential SQL Injection: String formatting used in cr.execute()."),
                    (r'eval\(', "Usage of eval() which can lead to Code Injection.")
                ],
                "file_types": [".py"]
            },
            {
                "id": "A08:2025",
                "name": "Software or Data Integrity Failures",
                "description": "Insecure deserialization.",
                "patterns": [
                    (r'pickle\.loads\(', "Insecure deserialization using pickle."),
                    (r'yaml\.load\(', "Insecure YAML loading. Use safe_load instead.")
                ],
                "file_types": [".py"]
            },
            {
                "id": "A09:2025",
                "name": "Logging & Alerting Failures",
                "description": "Missing logging on exception handling.",
                "patterns": [
                    (r'except\s+Exception[^:]*:\s*\n\s+pass', "Broad exception caught and ignored without logging.")
                ],
                "file_types": [".py"]
            },
            {
                "id": "A10:2025",
                "name": "Mishandling of Exceptional Conditions",
                "description": "Poor exception handling that may lead to information leakage or unpredictable states.",
                "patterns": [
                    (r'except\s+:\s*\n\s+pass', "Bare except clause ignoring errors.")
                ],
                "file_types": [".py"]
            }
        ]

    def scan_zip(self, zip_path: str) -> Dict[str, Any]:
        results = []
        counts = {rule["id"]: 0 for rule in self.rules}
        
        has_access_csv = False
        
        with tempfile.TemporaryDirectory() as extract_dir:
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
            except zipfile.BadZipFile:
                return {"error": "Invalid ZIP file."}

            for root, _, files in os.walk(extract_dir):
                for file in files:
                    if file == "ir.model.access.csv":
                        has_access_csv = True
                    
                    file_ext = os.path.splitext(file)[1].lower()
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, extract_dir)
                    
                    # Read file content safely
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                    except UnicodeDecodeError:
                        continue # Skip non-text files
                        
                    for rule in self.rules:
                        if file_ext in rule["file_types"]:
                            for pattern, message in rule["patterns"]:
                                for match in re.finditer(pattern, content):
                                    line_no = content.count('\n', 0, match.start()) + 1
                                    results.append({
                                        "category": rule["id"],
                                        "category_name": rule["name"],
                                        "file": rel_path,
                                        "line": line_no,
                                        "message": message
                                    })
                                    counts[rule["id"]] += 1
                                    
        if not has_access_csv:
            results.append({
                "category": "A01:2025",
                "category_name": "Broken Access Control",
                "file": "Security Check",
                "line": 0,
                "message": "Module is missing ir.model.access.csv file. Models might be inaccessible or overly permissive."
            })
            counts["A01:2025"] += 1
            
        score = max(0, 100 - (len(results) * 5))
        
        return {
            "score": score,
            "total_issues": len(results),
            "counts": counts,
            "findings": results
        }
