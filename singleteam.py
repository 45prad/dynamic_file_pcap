#!/usr/bin/env python3
"""
Team Challenge Generator for AI Anomaly Detection
Generates unique challenges for each team with different team identifiers
"""

import json
import random
import string
import os
from datetime import datetime

class TeamChallengeGenerator:
    def __init__(self):
        """Initialize the team challenge generator"""
        self.base_sequences = {
            1: "666c6167",      # "flag"
            2: "7b34695f",      # "{4i_"
            3: "346e306d",      # "4n0m" (will be corrupted)
            4: "346c795f",      # "4ly_" (will be corrupted)
            5: "64337433",      # "d3t3"
            6: "637433645f",    # "ct3d_"
            # Sequence 7 will be generated per team
        }
        
        self.corruptions = {
            3: "346ex0x6",      # 346e306d corrupted
            4: "346c79yf"       # 346c795f corrupted
        }
        
    def generate_team_id(self, length=6):
        """Generate a random team identifier"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choices(chars, k=length))
    
    def create_team_sequence7(self, team_id):
        """Create sequence 7 hex for specific team"""
        team_ending = f"{team_id}"
        return team_ending.encode('ascii').hex()
    
    def generate_team_challenge(self, team_name, team_id=None, output_dir="teams"):
        """Generate challenge for a specific team"""
        
        # Generate team ID if not provided
        if not team_id:
            team_id = self.generate_team_id()
        
        # Create sequence 7 for this team
        seq7_hex = self.create_team_sequence7(team_id)
        
        # Build complete sequences
        all_sequences = self.base_sequences.copy()
        all_sequences[7] = seq7_hex
        
        # Expected flag for this team
        expected_flag = f"flag{{4i_4n0m4ly_d3t3ct3d_{team_id}}}"
        
        # Create challenge data
        challenge_data = {
            "challenge_name": "Ghost in the Machine - AI Anomaly Detection",
            "description": f"CRITICAL: Our AI-powered network monitoring system (NEURAL-WATCH v2.3) detected a sophisticated data exfiltration attack using advanced evasion techniques. The attacker deployed leet speak encoding to bypass ML-based detection systems.",
            "team_info": {
                "team_name": team_name,
                "team_id": team_id,
                "expected_flag": expected_flag,
                "generated_at": datetime.now().isoformat()
            },
            "corruption_notice": "WARNING: Some log entries contain character substitution corruption designed to evade AI detection systems.",
            "ai_model_output": {
                "model_name": "NEURAL-WATCH v2.3",
                "analysis_window": "2024-06-15 08:00:00 to 2024-06-15 18:00:00 UTC",
                "corruption_detected": True,
                "ai_confidence_degraded": True,
                "evasion_techniques": [
                    "Leet speak character substitution",
                    "Multi-layer encoding obfuscation", 
                    "Character corruption patterns",
                    "AI model confusion attacks"
                ],
                "flagged_hosts": [
                    {
                        "host": "192.168.1.157",
                        "confidence": 0.89,
                        "pattern_type": "leet_speak_evasion",
                        "anomaly": "Character substitution detected in request headers",
                        "corruption_level": "MEDIUM",
                        "ai_bypass_detected": True
                    }
                ]
            },
            "network_logs": [
                {
                    "timestamp": "2024-06-15 08:23:17",
                    "src_ip": "192.168.1.157",
                    "dst_ip": "203.113.67.42",
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "tls_sni": "update-service.microsoft-analytics.com",
                    "custom_header": f"X-Request-ID: {all_sequences[1]}",
                    "sequence_num": 1,
                    "checksum": "a3f7",
                    "encryption_layer": "none"
                },
                {
                    "timestamp": "2024-06-15 08:38:22",
                    "src_ip": "192.168.1.157",
                    "dst_ip": "203.113.67.42",
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "tls_sni": "update-service.microsoft-analytics.com",
                    "custom_header": f"X-Request-ID: {all_sequences[2]}",
                    "sequence_num": 2,
                    "checksum": "b4e8",
                    "encryption_layer": "none"
                },
                {
                    "timestamp": "2024-06-15 08:53:28",
                    "src_ip": "192.168.1.157",
                    "dst_ip": "203.113.67.42",
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "tls_sni": "update-service.microsoft-analytics.com",
                    "custom_header": f"X-Request-ID: {self.corruptions[3]}",
                    "sequence_num": 3,
                    "checksum": "c5f9",
                    "corruption_note": "Character substitution corruption - reverse the encoding to recover original",
                    "encryption_layer": "substitution_cipher"
                },
                {
                    "timestamp": "2024-06-15 09:08:14",
                    "src_ip": "192.168.1.157",
                    "dst_ip": "203.113.67.42",
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "tls_sni": "update-service.microsoft-analytics.com",
                    "custom_header": f"X-Request-ID: {self.corruptions[4]}",
                    "sequence_num": 4,
                    "checksum": "d6g0",
                    "corruption_note": "Single character substitution detected",
                    "encryption_layer": "bit_substitution"
                },
                {
                    "timestamp": "2024-06-15 09:23:45",
                    "src_ip": "192.168.1.157",
                    "dst_ip": "203.113.67.42",
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "tls_sni": "update-service.microsoft-analytics.com",
                    "custom_header": f"X-Request-ID: {all_sequences[5]}",
                    "sequence_num": 5,
                    "checksum": "e7h1",
                    "encryption_layer": "none"
                },
                {
                    "timestamp": "2024-06-15 09:38:51",
                    "src_ip": "192.168.1.157",
                    "dst_ip": "203.113.67.42",
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "tls_sni": "update-service.microsoft-analytics.com",
                    "custom_header": f"X-Request-ID: {all_sequences[6]}",
                    "sequence_num": 6,
                    "checksum": "f8i2",
                    "encryption_layer": "none"
                },
                {
                    "timestamp": "2024-06-15 11:23:17",
                    "src_ip": "192.168.1.157",
                    "dst_ip": "203.113.67.42",
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "tls_sni": "update-service.microsoft-analytics.com",
                    "custom_header": f"X-Request-ID: {all_sequences[7]}",
                    "sequence_num": 7,
                    "checksum": "g9j3",
                    "corruption_note": "Base16 encoded team identifier - contains unique team data",
                    "encryption_layer": "base16_encoded",
                    "final_segment": True
                }
            ],
            "recovery_metadata": {
                "original_sequence_count": 7,
                "corrupted_sequences": [3, 4],
                "corruption_pattern": "AI evasion through leet speak and character substitution",
                "team_specific_data": {
                    "sequence_7_contains": "Unique team identifier",
                    "expected_format": "flag{4i_4n0m4ly_d3t3ct3d_[TEAM_ID]}"
                }
            },
            "additional_context": {
                "threat_intel": {
                    "203.113.67.42": "Clean - Microsoft Azure region"
                },
                "host_information": {
                    "192.168.1.157": "Windows 10 workstation - Finance department (CONFIRMED COMPROMISED - AI BYPASS DETECTED)"
                },
                "ai_analysis": {
                    "neural_watch_status": "COMPROMISED",
                    "confidence_degradation": "47%",
                    "evasion_techniques_detected": [
                        "Leet speak encoding (4→4i, a→4, e→3)",
                        "Character substitution patterns",
                        "ML model confusion attacks"
                    ]
                }
            },
            "flag_format": "flag{4i_4n0m4ly_d3t3ct3d_[TEAM_ID]}",
            "analysis_instructions": "Systematic reconstruction required: 1) Extract sequences from X-Request-ID headers, 2) Apply character substitution fixes, 3) Convert hex to ASCII, 4) Assemble complete flag with team identifier."
        }
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Save challenge file
        filename = f"{output_dir}/challenge_{team_name.lower().replace(' ', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(challenge_data, f, indent=2)
        
        return {
            "team_name": team_name,
            "team_id": team_id,
            "filename": filename,
            "expected_flag": expected_flag,
            "sequence_7_hex": seq7_hex
        }

def main():
    """Main function to generate a single team challenge with hardcoded values"""
    generator = TeamChallengeGenerator()
    
    # Hardcoded team details
    TEAM_NAME = "CyberDefenders"
    TEAM_ID = "cd1234"  # Hardcoded team ID
    
    print(f"🚀 Generating challenge for team: {TEAM_NAME} ({TEAM_ID})")
    
    result = generator.generate_team_challenge(TEAM_NAME, TEAM_ID)
    
    print(f"\n✅ Generated challenge for {result['team_name']}!")
    print(f"📁 File: {result['filename']}")
    print(f"🎯 Expected flag: {result['expected_flag']}")

if __name__ == "__main__":
    main()