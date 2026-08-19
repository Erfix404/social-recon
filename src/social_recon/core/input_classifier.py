"""Input Classifier — detects input type (username, email, phone, domain, name)."""
import re


def classify(target: str) -> tuple[str, str]:
    """Classify input and return (type, cleaned_value).

    Returns one of: "username", "email", "phone", "domain", "fullname", "unknown"
    """
    target = target.strip()

    # Remove leading @
    if target.startswith("@"):
        target = target[1:]

    # Email
    if re.match(r'^[\w.+-]+@[\w-]+\.[\w.]+$', target):
        return "email", target.lower()

    # Phone — Iranian format support
    digits_only = re.sub(r'[\s\-\(\)\+]', '', target)
    # Convert +98 to 0 prefix
    if digits_only.startswith("98") and len(digits_only) >= 12:
        digits_only = "0" + digits_only[2:]
    if re.match(r'^0?9\d{9}$', digits_only):
        if not digits_only.startswith("0"):
            digits_only = "0" + digits_only
        return "phone", digits_only
    # International phone
    if re.match(r'^[\+]?[\d]{7,15}$', digits_only) and len(digits_only) >= 8:
        return "phone", digits_only

    # Domain
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$', target):
        return "domain", target.lower()

    # Username (alphanumeric + dash/underscore/dot, 3-60 chars)
    if re.match(r'^[a-zA-Z0-9_.-]+$', target) and 3 <= len(target) <= 60:
        return "username", target

    # Full name (contains space, 2+ words)
    if " " in target and len(target.split()) >= 2:
        return "fullname", target

    return "unknown", target


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1:
        t = sys.argv[1]
        itype, clean = classify(t)
        print(json.dumps({"input": t, "type": itype, "clean": clean}, indent=2))
