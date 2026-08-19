#!/usr/bin/env python3
"""Input Classifier — detects input type (username, email, phone, domain, name)"""
import re

def classify(target):
    target = target.strip().replace("@", "").strip()
    
    # Email
    if re.match(r'^[\w.+-]+@[\w-]+\.[\w.]+$', target):
        return "email", target
    
    # Phone
    digits_only = re.sub(r'[\s\-\(\)\+]', '', target)
    if re.match(r'^[\+]?[\d]{7,15}$', digits_only) and len(digits_only) >= 8:
        return "phone", digits_only
    
    # Domain
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$', target):
        return "domain", target
    
    # Username (alphanumeric + dash/underscore)
    if re.match(r'^[a-zA-Z0-9_.-]+$', target) and 3 <= len(target) <= 60:
        return "username", target
    
    # Full name
    if " " in target and len(target.split()) >= 2:
        return "fullname", target
    
    return "unknown", target

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        t = sys.argv[1]
        itype, clean = classify(t)
        print(json.dumps({"input": t, "type": itype, "clean": clean}, indent=2))
    else:
        print("Usage: python3 input_classifier.py <target>")
