import hashlib
import json
import base64


def Encoded(s):
    encoded = base64.urlsafe_b64encode(s.encode()).decode()
    return encoded

expected_hashes = {
    "067b3418a2cd4783cf2e725ddc690fbefff1acb94969a9651b4bd34baaef2bde",  #  
    "09aa5090691740cbec29b0a8bbbe1350e7ad8f0fb14eff3e8870a438338d349c",  # 
    "7ff98bd0117b14c21b97fb36c65d69c0a06f65341595ebc9be74e719cbf3d2f2"   # 
}


with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

tokens = config.get("blocked_tokens", [])

matched_hashes = set()
for token in tokens:
    encoded_token = Encoded(token)
    token_hash = hashlib.sha256(encoded_token.encode()).hexdigest()
    if token_hash in expected_hashes:
        matched_hashes.add(token_hash)

if matched_hashes == expected_hashes:
    print("✅ SUCCESS: All IoCs matched using config.json.")
    
else:
    print("❌ Incomplete or failed detection.")
    print(f"Matched: {len(matched_hashes)} / {len(expected_hashes)}")
    print("Hint: Check if config.json contains all required tokens (after base92 encoding).")
