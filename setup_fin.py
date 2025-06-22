#!/usr/bin/env python3
"""
The Distributed Sleeper - Realistic Blue Team Challenge Generator
Creates challenge data with progressive hints for discovery

Usage: python lunar_sleeper_realistic.py TEAM_ID
Output: incident_data_TEAM_ID.json
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

class RealisticChallengeGenerator:
    def __init__(self, team_id: str):
        self.team_id = team_id
        self.eclipse_date = "2024/10/14 18:55:18"
        
    def create_obfuscated_script(self) -> str:
        """Create the main obfuscated payload with embedded hints"""
        
        # The core script with helpful comments
        script_code = f'''
# Astronomical Data Processing Module v2.1
# Author: SecurityResearch Team
# Purpose: Lunar phase correlation analysis
# Dependencies: hashlib, base64, json, datetime
# Key derivation method: SHA256(prefix + team_id + astronomical_reference)
# Encryption: XOR with team-derived key for payload protection

import hashlib
import base64
import json
from datetime import datetime

class AstronomicalCrypto:
    """
    Cryptographic module for astronomical event correlation
    Uses lunar eclipse timing for key generation
    """
    def __init__(self):
        self.team_id = "{self.team_id}"
        self.eclipse_timestamp = "2024/10/14 18:55:18"  # Lunar eclipse reference
        self.lunar_key = self._derive_lunar_key()
    
    def _derive_lunar_key(self):
        """
        Derive encryption key from astronomical event timing
        Format: LUNAR_ECLIPSE_2024_<team_id>_<timestamp>
        """
        base = f"LUNAR_ECLIPSE_2024_{{self.team_id}}_{{self.eclipse_timestamp}}"
        return hashlib.sha256(base.encode()).hexdigest()[:32]
    
    def encrypt_data(self, data):
        """XOR encryption with lunar-derived key"""
        key_bytes = self.lunar_key.encode()
        data_bytes = data.encode() if isinstance(data, str) else data
        encrypted = bytes(data_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data_bytes)))
        return base64.b64encode(encrypted).decode()
    
    def get_flag_component(self):
        """Generate the team's flag component using astronomical correlation"""
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
        """Generate encrypted payload for blockchain storage"""
        flag_data = self.get_flag_component()
        payload = {{
            "timestamp": datetime.now().isoformat(),
            "team_validation": self.team_id,
            "lunar_alignment": "eclipse_optimal", 
            "flag_hash": flag_data["hash"],
            "extraction_key": self.lunar_key,
            "mission_status": "COMPLETE"
        }}
        
        encrypted_payload = self.encrypt_data(json.dumps(payload))
        return {{
            "raw_payload": payload,
            "encrypted_payload": encrypted_payload,
            "decryption_hint": "Use lunar_key derived from eclipse_timestamp"
        }}

# Execution entry point
if __name__ == "__main__":
    crypto = AstronomicalCrypto()
    result = crypto.generate_blockchain_payload()
    print("BLOCKCHAIN_READY:", result["encrypted_payload"])
    print("FLAG_COMPONENT:", crypto.get_flag_component()["hash"])
'''
        
        # Multi-layer obfuscation with discoverable signatures
        # 1. Compile to bytecode
        compiled = compile(script_code, f'<lunar_payload_{self.team_id}>', 'exec')
        bytecode = marshal.dumps(compiled)
        
        # 2. Compress with zlib (recognizable magic bytes)
        compressed = zlib.compress(bytecode)
        
        # 3. Base64 encode
        b64_encoded = base64.b64encode(compressed).decode()
        
        # 4. XOR with discoverable team key
        xor_key = hashlib.md5(f"lunar_{self.team_id}".encode()).digest()
        xor_result = bytes(
            b64_encoded.encode()[i] ^ xor_key[i % len(xor_key)]
            for i in range(len(b64_encoded.encode()))
        )
        
        # 5. Final base64 encoding
        final_payload = base64.b64encode(xor_result).decode()
        
        return final_payload
    
    def generate_investigation_tips(self) -> List[str]:
        """Generate realistic investigation tips that provide progressive hints"""
        return [
            "📋 INCIDENT TIMELINE:",
            "- 2024-03-10: Anomalous AWS Lambda execution patterns detected",
            "- 2024-03-15: Elevated memory usage in data processing functions",  
            "- 2024-03-20: Suspicious blockchain transaction activity observed",
            "- 2024-03-25: Pattern correlation with astronomical events noted",
            "",
            "🔍 ANALYSIS PRIORITIES:",
            "1. Focus on Lambda functions with execution times >8000ms",
            "2. Examine environment variables in suspicious executions",
            "3. Look for base64-encoded data in execution contexts",
            "4. Correlate timing with lunar calendar events",
            "5. Analyze blockchain transactions for data storage patterns",
            "",
            "🛠️ RECOMMENDED TOOLS:",
            "- Standard base64 decode utilities",
            "- File analysis tools (file, hexdump)",
            "- Compression detection (zlib magic bytes: 0x789c)",
            "- XOR analysis with team-derived keys",
            "- Python marshal/bytecode analysis tools",
            "",
            "💡 KEY INDICATORS:",
            "- Environment variables containing large encoded strings",
            "- Function names referencing 'lunar' or 'astronomical' themes",
            "- Compression artifacts in decoded payloads",
            "- Team identifier references in execution context",
            "- Blockchain events with encrypted data storage",
            "",
            "🔑 DECRYPTION HINTS:",
            "- XOR keys often derived from team identifiers",
            "- Try MD5 hashing team names with prefixes (lunar_, astro_, etc.)",
            "- Astronomical timestamps used in key derivation",
            "- Look for lunar eclipse references: 2024/10/14 format",
            "- SHA256 commonly used for final key generation",
            "",
            "⚠️ COMMON PITFALLS:",
            "- Multiple base64 layers may be present",
            "- Check for zlib magic bytes after XOR decryption",
            "- Python bytecode requires marshal.loads() for execution",
            "- Blockchain data may require additional decryption",
            "- Flag format: FLAG{STATIC_DYNAMIC_HASH}"
        ]
    
    def generate_aws_logs(self) -> List[Dict[str, Any]]:
        """Generate AWS CloudWatch logs with embedded hints and realistic noise"""
        
        logs = []
        obfuscated_payload = self.create_obfuscated_script()
        base_date = datetime(2024, 3, 10)
        
        # Generate 150 log entries with progressive hint distribution
        for i in range(150):
            log_time = base_date + timedelta(hours=i*4, minutes=random.randint(0, 59))
            
            # 8% of logs contain investigation hints
            if i % 12 == 0:  
                log_entry = {
                    "timestamp": log_time.isoformat() + "Z",
                    "requestId": f"req-{random.randint(100000, 999999)}",
                    "functionName": "astronomical-data-processor",
                    "logLevel": "INFO",
                    "duration": random.randint(8500, 12000),  # Suspicious duration
                    "memoryUsed": random.randint(850, 950),   # High memory usage
                    "message": "Astronomical correlation analysis completed",
                    "environment": {
                        "AWS_REGION": "us-east-1",
                        "FUNCTION_VERSION": "$LATEST",
                        "TEAM_IDENTIFIER": self.team_id,
                        "PROCESSING_MODE": "lunar_correlation",
                        "DATA_ENCODING": "multi_layer_protection",
                        "KEY_DERIVATION_METHOD": "team_astronomical_hash",
                        "REFERENCE_TIMESTAMP": self.eclipse_date,
                        "COMPRESSION_ENABLED": "true",
                        "PAYLOAD_DATA": obfuscated_payload,  # The main challenge
                        "DECODE_SEQUENCE": "b64_xor_b64_zlib_marshal",
                        "XOR_KEY_FORMAT": "md5(lunar_TEAM_ID)"
                    },
                    "customMetrics": {
                        "lunarAlignment": 0.92,
                        "eclipseProximity": 0.85,
                        "payloadSize": len(obfuscated_payload),
                        "encodingLayers": 5
                    },
                    "errorDetails": None
                }
                
            # 5% contain partial hints
            elif i % 20 == 0:
                log_entry = {
                    "timestamp": log_time.isoformat() + "Z",
                    "requestId": f"req-{random.randint(100000, 999999)}",
                    "functionName": "data-compression-handler",
                    "logLevel": "DEBUG",
                    "duration": random.randint(2000, 4000),
                    "memoryUsed": random.randint(200, 400),
                    "message": "Payload compression successful using zlib",
                    "environment": {
                        "COMPRESSION_TYPE": "zlib",
                        "MAGIC_BYTES": "789c",
                        "TEAM_CONTEXT": self.team_id,
                        "ENCODING_LAYERS": "multiple"
                    }
                }
                
            # 3% contain XOR hints  
            elif i % 33 == 0:
                log_entry = {
                    "timestamp": log_time.isoformat() + "Z",
                    "requestId": f"req-{random.randint(100000, 999999)}",
                    "functionName": "encryption-service",
                    "logLevel": "INFO", 
                    "duration": random.randint(1500, 3000),
                    "memoryUsed": random.randint(150, 300),
                    "message": "XOR encryption completed with team-derived key",
                    "environment": {
                        "ENCRYPTION_METHOD": "xor",
                        "KEY_SOURCE": f"md5(lunar_{self.team_id})",
                        "KEY_LENGTH": "16_bytes",
                        "TEAM_PREFIX": "lunar_"
                    }
                }
                
            else:  # 84% normal logs
                log_entry = {
                    "timestamp": log_time.isoformat() + "Z",
                    "requestId": f"req-{random.randint(100000, 999999)}",
                    "functionName": random.choice([
                        "api-gateway-handler", "user-auth-service", "payment-processor",
                        "email-notification", "database-sync", "image-resize-service",
                        "cache-manager", "webhook-dispatcher", "report-generator"
                    ]),
                    "logLevel": random.choice(["INFO", "WARN", "DEBUG"]),
                    "duration": random.randint(100, 2000),
                    "memoryUsed": random.randint(50, 200),
                    "message": random.choice([
                        "Request processed successfully",
                        "User authentication completed", 
                        "Database operation finished",
                        "API response generated",
                        "Cache invalidation successful"
                    ]),
                    "environment": {
                        "AWS_REGION": "us-east-1",
                        "FUNCTION_VERSION": "$LATEST"
                    }
                }
            
            logs.append(log_entry)
        
        return logs
    
    def generate_blockchain_logs(self) -> List[Dict[str, Any]]:
        """Generate blockchain transaction logs with encrypted evidence"""
        
        transactions = []
        base_date = datetime(2024, 3, 15)
        
        # Execute script to get blockchain payload
        crypto_instance = self._execute_script_for_payload()
        
        # Generate 250 transactions with 4% containing evidence
        for i in range(250):
            tx_time = base_date + timedelta(hours=i*2, minutes=random.randint(0, 59))
            
            if i % 25 == 0 and crypto_instance:  # 4% evidence transactions
                blockchain_data = crypto_instance.generate_blockchain_payload()
                
                tx = {
                    "hash": f"0x{hashlib.sha256(f'evidence_tx_{self.team_id}_{i}'.encode()).hexdigest()}",
                    "blockNumber": 1000000 + i//10,
                    "timestamp": tx_time.isoformat(),
                    "from": f"0x{hashlib.sha256(self.team_id.encode()).hexdigest()[:40]}",
                    "to": "0x742d35Cc6634C0532925a3b8D8A8E1c5E1a49C8b",  # Evidence contract
                    "value": 0,
                    "gas": 150000,
                    "status": "success",
                    "logs": [{
                        "address": "0x742d35Cc6634C0532925a3b8D8A8E1c5E1a49C8b",
                        "topics": [
                            "0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6",  # EvidenceStored
                            f"0x{hashlib.sha256(self.team_id.encode()).hexdigest()}"  # team_id indexed
                        ],
                        "data": blockchain_data["encrypted_payload"],
                        "decoded_hint": "Use lunar_key for XOR decryption",
                        "team_marker": self.team_id,
                        "encryption_method": "xor_with_astronomical_key"
                    }]
                }
            else:  # Normal transactions
                tx = {
                    "hash": f"0x{hashlib.sha256(f'tx_{i}_{random.randint(1000,9999)}'.encode()).hexdigest()}",
                    "blockNumber": 1000000 + i//10,
                    "timestamp": tx_time.isoformat(),
                    "from": f"0x{hashlib.sha256(f'addr_{i}'.encode()).hexdigest()[:40]}",
                    "to": f"0x{hashlib.sha256(f'addr_{i+1}'.encode()).hexdigest()[:40]}",
                    "value": random.randint(1000000000, 10000000000000000000),
                    "gas": random.randint(21000, 100000),
                    "status": "success"
                }
            
            transactions.append(tx)
        
        return transactions
    
    def _execute_script_for_payload(self):
        """Execute the script to generate blockchain payload"""
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
        payload = {{"timestamp": datetime.now().isoformat(), "team_validation": self.team_id, "lunar_alignment": "eclipse_optimal", "flag_hash": flag_data["hash"], "extraction_key": self.lunar_key, "mission_status": "COMPLETE"}}
        encrypted_payload = self.encrypt_data(json.dumps(payload))
        return {{"raw_payload": payload, "encrypted_payload": encrypted_payload, "decryption_hint": "Use lunar_key derived from eclipse_timestamp"}}

crypto = AstronomicalCrypto()
'''
            namespace = {}
            exec(script_code, namespace)
            return namespace.get('crypto')
        except:
            return None
    
    def generate_complete_challenge(self) -> Dict[str, Any]:
        """Generate the complete realistic challenge data"""
        
        print(f"🌙 Generating realistic challenge for team: {self.team_id}")
        
        aws_logs = self.generate_aws_logs()
        blockchain_logs = self.generate_blockchain_logs()
        investigation_tips = self.generate_investigation_tips()
        
        challenge_data = {
            "incident_metadata": {
                "case_number": f"INC-2024-{random.randint(1000, 9999)}",
                "incident_type": "Advanced Persistent Threat (APT)",
                "severity": "CRITICAL",
                "first_detected": "2024-03-10T14:30:00Z",
                "last_activity": "2024-03-25T09:15:00Z",
                "affected_systems": ["AWS Lambda", "Blockchain Network"],
                "investigation_status": "ACTIVE - Requires Analysis"
            },
            
            "investigation_notes": investigation_tips,
            
            "aws_cloudwatch_logs": aws_logs,
            
            "blockchain_transactions": blockchain_logs,
            
            "analyst_guidance": {
                "start_here": "Begin with AWS logs - look for anomalous execution patterns",
                "key_functions": "Focus on functions with 'astronomical' or 'lunar' themes",
                "encoding_analysis": "Expect multiple layers of encoding/encryption",
                "time_correlation": "Activity may correlate with astronomical events",
                "blockchain_focus": "Evidence storage in smart contract events",
                "success_criteria": "Extract flag in format FLAG{STATIC_DYNAMIC_HASH}"
            }
        }
        
        return challenge_data
    
    def save_challenge(self, output_file: str = None):
        """Save the complete challenge to a JSON file"""
        
        if not output_file:
            output_file = f"incident_data_{self.team_id}.json"
        
        challenge_data = self.generate_complete_challenge()
        
        with open(output_file, 'w') as f:
            json.dump(challenge_data, f, indent=2)
        
        import os
        size_mb = os.path.getsize(output_file) / (1024 * 1024)
        
        print(f"✅ Incident data package generated!")
        print(f"📁 File: {output_file} ({size_mb:.1f} MB)")
        print(f"🔍 AWS log entries: {len(challenge_data['aws_cloudwatch_logs'])}")
        print(f"⛓️  Blockchain transactions: {len(challenge_data['blockchain_transactions'])}")
        print(f"📋 Investigation guidance included")
        print(f"🎯 Progressive hints embedded throughout data")
        
        return output_file

def main():
    if len(sys.argv) != 2:
        print("Usage: python lunar_sleeper_realistic.py TEAM_ID")
        print("Example: python lunar_sleeper_realistic.py ALPHA_7")
        sys.exit(1)
    
    team_id = sys.argv[1]
    
    print(f"🚀 Generating realistic blue team challenge...")
    print(f"👥 Team ID: {team_id}")
    
    generator = RealisticChallengeGenerator(team_id)
    output_file = generator.save_challenge()
    
    print(f"\n🎉 Challenge ready for blue team analysis!")
    print(f"📦 Provide analysts with: {output_file}")
    print(f"⏱️  Expected analysis time: 3-5 hours with progressive discovery")
    print(f"🔍 Hints are embedded naturally throughout the incident data")

if __name__ == "__main__":
    main()