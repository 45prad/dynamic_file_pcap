#!/usr/bin/env python3
"""
The Distributed Sleeper - Complete CTF Challenge Generator
Single file that generates everything needed for the challenge

Usage: python lunar_sleeper_generator.py TEAM_ID
Output: lunar_sleeper_TEAM_ID.json (contains all challenge data)
"""

import json
import base64
import marshal
import hashlib
import zlib
import random
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, List

class LunarSleeperGenerator:
    def __init__(self, team_id: str):
        self.team_id = team_id
        self.eclipse_date = "2024/10/14 18:55:18"
        
    def create_obfuscated_script(self) -> str:
        """Create the main obfuscated payload with astronomical crypto"""
        
        # The core script participants need to reverse engineer
        script_code = f'''
import hashlib
import base64
import json
from datetime import datetime

class AstronomicalCrypto:
    def __init__(self):
        self.team_id = "{self.team_id}"
        self.eclipse_timestamp = "2024/10/14 18:55:18"
        self.lunar_key = self._derive_lunar_key()
    
    def _derive_lunar_key(self):
        """Derive encryption key from astronomical event"""
        base = f"LUNAR_ECLIPSE_2024_{{self.team_id}}_{{self.eclipse_timestamp}}"
        return hashlib.sha256(base.encode()).hexdigest()[:32]
    
    def encrypt_data(self, data):
        """Simple XOR encryption with lunar key"""
        key_bytes = self.lunar_key.encode()
        data_bytes = data.encode() if isinstance(data, str) else data
        
        encrypted = bytes(
            data_bytes[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(data_bytes))
        )
        return base64.b64encode(encrypted).decode()
    
    def get_flag_component(self):
        """Generate the team's flag component"""
        static_part = "LUNAR_ECLIPSE_2024"
        combined = f"{{static_part}}_{{self.team_id}}"
        hash_suffix = hashlib.sha256(combined.encode()).hexdigest()[-8:].upper()
        
        return {{
            "static": static_part,
            "dynamic": self.team_id,
            "hash": hash_suffix,
            "complete_flag": f"FLAG{{{{{{static_part}}_{{self.team_id}}_{{hash_suffix}}}}}}"
        }}
    
    def generate_blockchain_payload(self):
        """Generate payload for blockchain storage"""
        flag_data = self.get_flag_component()
        
        payload = {{
            "timestamp": datetime.now().isoformat(),
            "team_validation": self.team_id,
            "lunar_alignment": "eclipse_optimal",
            "flag_hash": flag_data["hash"],
            "extraction_key": self.lunar_key,
            "success": True
        }}
        
        # Encrypt the payload
        encrypted_payload = self.encrypt_data(json.dumps(payload))
        
        return {{
            "raw_payload": payload,
            "encrypted_payload": encrypted_payload,
            "decryption_hint": "Use lunar_key derived from eclipse_timestamp"
        }}

# Main execution
if __name__ == "__main__":
    crypto = AstronomicalCrypto()
    result = crypto.generate_blockchain_payload()
    print("BLOCKCHAIN_READY:", result["encrypted_payload"])
    print("FLAG_COMPONENT:", crypto.get_flag_component()["hash"])
'''
        
        # Multi-layer obfuscation
        # 1. Compile to bytecode
        compiled = compile(script_code, f'<lunar_payload_{self.team_id}>', 'exec')
        bytecode = marshal.dumps(compiled)
        
        # 2. Compress
        compressed = zlib.compress(bytecode)
        
        # 3. Base64 encode
        b64_encoded = base64.b64encode(compressed).decode()
        
        # 4. XOR with team-based key
        xor_key = hashlib.md5(f"lunar_{self.team_id}".encode()).digest()
        xor_result = bytes(
            b64_encoded.encode()[i] ^ xor_key[i % len(xor_key)]
            for i in range(len(b64_encoded.encode()))
        )
        
        # 5. Final base64 encoding
        final_payload = base64.b64encode(xor_result).decode()
        
        return final_payload
    
    def generate_blockchain_logs(self) -> List[Dict[str, Any]]:
        """Generate blockchain transaction logs with hidden flag data"""
        
        transactions = []
        base_date = datetime(2024, 3, 15)  # Near lunar eclipse
        
        # Generate 200 realistic transactions
        for i in range(200):
            tx_time = base_date + timedelta(hours=i*2, minutes=random.randint(0, 59))
            
            # 95% normal transactions
            if i % 20 != 0:  # Normal transaction
                tx = {
                    "hash": f"0x{hashlib.sha256(f'tx_{self.team_id}_{i}'.encode()).hexdigest()}",
                    "blockNumber": 1000000 + i//10,
                    "from": f"0x{hashlib.sha256(f'addr_{i}'.encode()).hexdigest()[:40]}",
                    "to": f"0x{hashlib.sha256(f'addr_{i+1}'.encode()).hexdigest()[:40]}",
                    "value": random.randint(1000000000, 10000000000000000000),
                    "gas": random.randint(21000, 500000),
                    "timestamp": tx_time.isoformat(),
                    "status": "success"
                }
            else:  # Special transaction with flag data
                # Execute our obfuscated script to get the encrypted payload
                crypto_instance = self._execute_obfuscated_script()
                blockchain_data = crypto_instance.generate_blockchain_payload() if crypto_instance else None
                
                tx = {
                    "hash": f"0x{hashlib.sha256(f'flag_tx_{self.team_id}_{i}'.encode()).hexdigest()}",
                    "blockNumber": 1000000 + i//10,
                    "from": f"0x{hashlib.sha256(self.team_id.encode()).hexdigest()[:40]}",
                    "to": "0x742d35Cc6634C0532925a3b8D8A8E1c5E1a49C8b",  # Contract address
                    "value": 0,
                    "gas": 150000,
                    "timestamp": tx_time.isoformat(),
                    "status": "success",
                    "logs": [{
                        "address": "0x742d35Cc6634C0532925a3b8D8A8E1c5E1a49C8b",
                        "topics": [
                            "0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6",  # EvidenceStored
                            f"0x{hashlib.sha256(self.team_id.encode()).hexdigest()}"  # team_id indexed
                        ],
                        "data": blockchain_data["encrypted_payload"] if blockchain_data else "0x00",
                        "team_marker": self.team_id,
                        "lunar_alignment": "eclipse_optimal"
                    }] if blockchain_data else []
                }
            
            transactions.append(tx)
        
        return transactions
    
    def _execute_obfuscated_script(self):
        """Execute the obfuscated script to get crypto instance"""
        try:
            script_code = f'''
import hashlib
import base64
import json
from datetime import datetime

class AstronomicalCrypto:
    def __init__(self):
        self.team_id = "{self.team_id}"
        self.eclipse_timestamp = "2024/10/14 18:55:18"
        self.lunar_key = self._derive_lunar_key()
    
    def _derive_lunar_key(self):
        base = f"LUNAR_ECLIPSE_2024_{{self.team_id}}_{{self.eclipse_timestamp}}"
        return hashlib.sha256(base.encode()).hexdigest()[:32]
    
    def encrypt_data(self, data):
        key_bytes = self.lunar_key.encode()
        data_bytes = data.encode() if isinstance(data, str) else data
        encrypted = bytes(data_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data_bytes)))
        return base64.b64encode(encrypted).decode()
    
    def get_flag_component(self):
        static_part = "LUNAR_ECLIPSE_2024"
        combined = f"{{static_part}}_{{self.team_id}}"
        hash_suffix = hashlib.sha256(combined.encode()).hexdigest()[-8:].upper()
        return {{"static": static_part, "dynamic": self.team_id, "hash": hash_suffix, "complete_flag": f"FLAG{{{{{{static_part}}_{{self.team_id}}_{{hash_suffix}}}}}}"}}
    
    def generate_blockchain_payload(self):
        flag_data = self.get_flag_component()
        payload = {{"timestamp": datetime.now().isoformat(), "team_validation": self.team_id, "lunar_alignment": "eclipse_optimal", "flag_hash": flag_data["hash"], "extraction_key": self.lunar_key, "success": True}}
        encrypted_payload = self.encrypt_data(json.dumps(payload))
        return {{"raw_payload": payload, "encrypted_payload": encrypted_payload, "decryption_hint": "Use lunar_key derived from eclipse_timestamp"}}

crypto = AstronomicalCrypto()
'''
            namespace = {}
            exec(script_code, namespace)
            return namespace.get('crypto')
        except:
            return None
    
    def generate_aws_logs(self) -> List[Dict[str, Any]]:
        """Generate AWS CloudWatch logs containing the obfuscated script"""
        
        logs = []
        obfuscated_payload = self.create_obfuscated_script()
        base_date = datetime(2024, 3, 10)
        
        # Generate 100 log entries with 5% containing the payload
        for i in range(100):
            log_time = base_date + timedelta(hours=i*6, minutes=random.randint(0, 59))
            
            if i % 20 == 0:  # 5% of logs contain the payload
                log_entry = {
                    "timestamp": log_time.isoformat() + "Z",
                    "requestId": f"req-{random.randint(100000, 999999)}",
                    "functionName": "lunar-data-processor",
                    "logLevel": "INFO",
                    "duration": random.randint(8000, 15000),
                    "memoryUsed": random.randint(800, 1000),
                    "message": "Astronomical data processing completed",
                    "environment": {
                        "AWS_REGION": "us-east-1",
                        "AWS_LAMBDA_FUNCTION_VERSION": "$LATEST",
                        "ENVIRONMENT": "production",
                        "TEAM_IDENTIFIER": self.team_id,  # KEY: Dynamic component
                        "DATA_PAYLOAD": obfuscated_payload,  # The main challenge (less obvious name)
                        "ENCODING_METHOD": "multi_layer",
                        "KEY_DERIVATION": "astronomical_source",
                        "REFERENCE_DATE": self.eclipse_date,
                        "CRYPTO_VERSION": "v2.1"
                    },
                    "customMetrics": {
                        "lunarAlignment": 0.95,
                        "eclipseProximity": 0.88,
                        "payloadActive": True
                    }
                }
            else:  # Normal log entry
                log_entry = {
                    "timestamp": log_time.isoformat() + "Z",
                    "requestId": f"req-{random.randint(100000, 999999)}",
                    "functionName": random.choice(["api-handler", "auth-service", "data-sync"]),
                    "logLevel": random.choice(["INFO", "WARN", "DEBUG"]),
                    "duration": random.randint(100, 3000),
                    "memoryUsed": random.randint(50, 300),
                    "message": random.choice([
                        "Request processed successfully",
                        "User authentication completed",
                        "Data synchronization finished"
                    ])
                }
            
            logs.append(log_entry)
        
        return logs
    
    def generate_complete_challenge(self) -> Dict[str, Any]:
        """Generate the complete challenge data"""
        
        print(f"🌙 Generating challenge for team: {self.team_id}")
        
        # Generate all components
        aws_logs = self.generate_aws_logs()
        blockchain_logs = self.generate_blockchain_logs()
        obfuscated_script = self.create_obfuscated_script()
        
        # Calculate expected flag
        static_part = "LUNAR_ECLIPSE_2024"
        combined = f"{static_part}_{self.team_id}"
        expected_hash = hashlib.sha256(combined.encode()).hexdigest()[-8:].upper()
        expected_flag = f"FLAG{{{combined}_{expected_hash}}}"
        
        challenge_data = {
            "metadata": {
                "challenge_name": "The Distributed Sleeper",
                "description": "Advanced persistent threat analysis - 6 months of suspicious activity detected",
                "generated_at": datetime.now().isoformat(),
                "data_sources": ["AWS CloudWatch", "Blockchain Network"],
                "time_period": "2024-02-01 to 2024-05-01",
                "alert_level": "CRITICAL"
            },
            
            "aws_cloudwatch_logs": aws_logs,
            
            "blockchain_transactions": blockchain_logs,
            
            "investigation_notes": {
                "initial_detection": "Anomalous Lambda execution patterns detected",
                "threat_indicators": "Suspicious astronomical timing correlations",
                "data_exfiltration": "Evidence of encrypted payload storage in blockchain",
                "analysis_priority": "Focus on Lambda functions with elevated execution times",
                "blockchain_focus": "Smart contract events during period of interest"
            }
        }
        
        return challenge_data
    
    def save_challenge(self, output_file: str = None):
        """Save the complete challenge to a JSON file"""
        
        if not output_file:
            output_file = f"lunar_sleeper_{self.team_id}.json"
        
        challenge_data = self.generate_complete_challenge()
        
        with open(output_file, 'w') as f:
            json.dump(challenge_data, f, indent=2)
        
        # Calculate file size
        import os
        size_mb = os.path.getsize(output_file) / (1024 * 1024)
        
        print(f"✅ Challenge generated successfully!")
        print(f"📁 File: {output_file} ({size_mb:.1f} MB)")
        print(f"🔍 AWS log entries: {len(challenge_data['aws_cloudwatch_logs'])}")
        print(f"⛓️  Blockchain transactions: {len(challenge_data['blockchain_transactions'])}")
        print(f"📊 Challenge complexity: Multi-phase reverse engineering required")
        print(f"🎯 Participants must analyze logs to reconstruct attack timeline")
        
        return output_file

def main():
    if len(sys.argv) != 2:
        print("Usage: python lunar_sleeper_generator.py TEAM_ID")
        print("Example: python lunar_sleeper_generator.py ALPHA_7")
        sys.exit(1)
    
    team_id = sys.argv[1]
    
    print(f"🚀 Starting Lunar Sleeper challenge generation...")
    print(f"👥 Team ID: {team_id}")
    
    generator = LunarSleeperGenerator(team_id)
    output_file = generator.save_challenge()
    
    print(f"\n🎉 Challenge ready!")
    print(f"📦 Give participants: {output_file}")
    print(f"⏱️  Estimated solve time: 4-6 hours for expert teams")

if __name__ == "__main__":
    main()