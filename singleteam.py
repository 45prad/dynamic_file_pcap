#!/usr/bin/env python3
"""
Single Team Challenge Generator
Just generates one challenge file - NO FLAG EXPOSED
"""

import json

def generate_team_challenge(team_name, team_id):
    """Generate challenge for specific team without exposing the flag"""
    
    # Base sequences (no flag info)
    base_sequences = {
        1: "666c6167",      # "flag"
        2: "7b34695f",      # "{4i_"
        5: "64337433",      # "d3t3"
        6: "637433645f",    # "ct3d_"
    }
    
    # Corrupted sequences
    corrupted_sequences = {
        3: "346ex0x6",      # corrupted version
        4: "346c79yf"       # corrupted version
    }
    
    # Generate team-specific sequence 7
    team_ending = f"{team_id}"
    seq7_hex = team_ending.encode('ascii').hex()
    
    # Create challenge data (NO FLAG INFO)
    challenge_data = {
        "challenge_name": "Ghost in the Machine - AI Anomaly Detection",
        "description": "CRITICAL: Our AI-powered network monitoring system (NEURAL-WATCH v2.3) detected a sophisticated data exfiltration attack using advanced evasion techniques. The attacker deployed leet speak encoding to bypass ML-based detection systems.",
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
                "custom_header": f"X-Request-ID: {base_sequences[1]}",
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
                "custom_header": f"X-Request-ID: {base_sequences[2]}",
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
                "custom_header": f"X-Request-ID: {corrupted_sequences[3]}",
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
                "custom_header": f"X-Request-ID: {corrupted_sequences[4]}",
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
                "custom_header": f"X-Request-ID: {base_sequences[5]}",
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
                "custom_header": f"X-Request-ID: {base_sequences[6]}",
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
                "custom_header": f"X-Request-ID: {seq7_hex}",
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
            "corruption_pattern": "AI evasion through leet speak and character substitution"
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
        "flag_format": "flag{l33t_sp34k_pattern}",
        "analysis_instructions": "Systematic reconstruction required: Extract sequences from X-Request-ID headers, apply character substitution fixes, convert hex to ASCII, assemble complete flag."
    }
    
    # Save challenge file
    filename = f"challenge_{team_name.lower().replace(' ', '_')}.json"
    with open(filename, 'w') as f:
        json.dump(challenge_data, f, indent=2)
    
    print(f"✅ Generated: {filename}")
    print(f"🎯 Team: {team_name}")
    print(f"🔑 Team ID: {team_id}")
    
    return filename

def main():
    """Main function - edit team name and ID here"""
    
    # EDIT THESE VALUES
    team_name = "Team C1"
    team_id = "af397af5"
    
    print("🚀 GENERATING TEAM CHALLENGE")
    print("=" * 30)
    
    filename = generate_team_challenge(team_name, team_id)
    
    print(f"\n📁 Generated: {filename}")
    print("🎯 NO FLAG EXPOSED - CLEAN CHALLENGE READY!")

if __name__ == "__main__":
    main()