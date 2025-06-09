
import hashlib
import json

# Expected SHA-256 hashes for hidden IoCs
expected_hashes = {
    "1aa4cb0bcca76e92e30677e809bb3d4b5c066715ef4d558184e319496bcc5125",  
    "1bbd174404efbce95f1af489ef93f4aa0f4d55718f24c3504682216afa7b7fb1",  
    "c4d0cf241a1bfa1c8bf4cf24e8f89d2ab786a284a39adb2fc8df7ea14e73c154"   
}

# Load config.json and extract tokens
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)


tokens = config.get("blocked_tokens", [])

# Compute hash of each token and check against expected
matched_hashes = set()
for token in tokens:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if token_hash in expected_hashes:
        matched_hashes.add(token_hash)

# Final result
if matched_hashes == expected_hashes:
    print("✅ SUCCESS: All IoCs matched using config.json.")
    
else:
    print("❌ Incomplete or failed detection.")
    print(f"Matched: {len(matched_hashes)} / {len(expected_hashes)}")
    print("Hint: Check if config.json contains all required tokens.")
