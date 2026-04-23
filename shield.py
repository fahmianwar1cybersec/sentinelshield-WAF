import re
from datetime import datetime
RULES = {
  "SQL Injection":r"('|\-\-|OR|SELECT|DROP|UNION)",
  "XSS (Script Attack)": r"(<script>|alert\(|javascript:|<|>)",
  "Directory Traversal": r"(\.\./|etc/passwd)"
}
def log_event(status, payload, attack_type="N/A"):
    with open("security_logs.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] STSTUS: {status} | PAYLOAD: {payload} | TYPE: {attack_type}\n"
        f.write(log_entry)

def inspect_request(payload):
  print(f"\n[INFO]Inspecting Request:{payload}")
  for attack_type, pattern in RULES.items():
     if re.search(pattern, payload, re.IGNORECASE):
        print(f"[ALERT] !!! {attack_type} DETECTED !!!")
        print("[ACTION] Request is BLOCKED by SENTINEL SHIELD.")
        log_event("BLOCKED", payload, attack_type)
        return
  print("[SUCCESS] Request is CLEAN.. Access Granted.")
  log_event("ALLOWED", payload)
print("--- SentinelShield Web Protection System---")
test_input = input("Enter an URL or Request Body to test:")
inspect_request(test_input)

