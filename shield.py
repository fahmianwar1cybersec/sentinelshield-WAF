from flask import Flask, request
import re

app = Flask(__name__)

# Detection Logic
def inspect_request(payload):
    patterns = {
        "SQL Injection": r"('|\"|--|#|UNION|SELECT|OR 1=1)",
        "XSS": r"(<script>|alert\(|onerror=)",
        "Directory Traversal": r"(\.\.\/|\/etc\/passwd)"
    }
    for attack_type, pattern in patterns.items():
        if re.search(pattern, payload, re.IGNORECASE):
            return f"BLOCKED: {attack_type} detected!"
    return "ALLOWED: Request is clean."

@app.route('/')
def home():
    # URL parameters check
    query = request.args.get('test', '')
    if query:
        result = inspect_request(query)
        return f"<h1>SentinelShield Analysis</h1><p>Payload: {query}</p><h2>Result: {result}</h2>"
    return "<h1>SentinelShield is LIVE</h1><p>Add <b>?test=your_payload</b> to the URL to test.</p>"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000)
