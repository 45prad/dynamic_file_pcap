from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
import requests
import os
import tempfile
import subprocess
import zipfile  # Using built-in zipfile instead of adm-zip
import shutil
import math
import random
import base64
import pandas as pd
from datetime import datetime, timedelta
from scapy.all import IP, UDP, DNS, DNSQR, wrpcap, rdpcap, Raw


app = Flask(__name__)
CORS(app)


#for all chllenges
CTF_BASE_URL = "https://ctf.cybersuraksha.co"

#pcapDeepDive challenge 
ORIGINAL_URL = b"110.81.92.57"
deepDivechallenge_id = "683fe143c6d6c84d40c6fc3f"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EXCEL_PATH = os.path.join(BASE_DIR, "deepdive_map.xlsx")
ORIGINAL_PCAP_PATH = os.path.join(BASE_DIR, "PcapDeepDive.pcap")


#chatgpt Challenge
chatgpt_challenge_id="683fe143c6d6c84d40c6fc3f"
INPUT_JS_PATH = "input.js" 
INPUT_JSON_PATH="manifest.json"
 # this should be in the same directory
PLACEHOLDER_MAP = {
    "flag{th1s_": 0,
    "1s_mult1": 1,
    "auth=stage_ct": 2,
    "f_ch4ll3": 3,
    "ng3_fin4": 4,
    "l_f1nd_m3}": 5
}

def split_flag_into_6_parts(flag):
    total_len = len(flag)
    if total_len < 6:
        raise ValueError("Flag must be at least 6 characters long.")

    base_size = total_len // 6
    extras = total_len % 6

    parts = []
    start = 0
    for i in range(6):
        size = base_size + (1 if i < extras else 0)
        parts.append(flag[start:start + size])
        start += size
    return parts



#comments challenge
challenge_id = "682c3e5b088e4ef9fb77763f"

# Configure these paths according to your system
EDITCAP_PATH = "C:\\Program Files\\Wireshark\\editcap.exe"
TSHARK_PATH = "C:\\Program Files\\Wireshark\\tshark.exe"
PCAP_DRIVE_URL = 'https://drive.google.com/uc?export=download&id=1PSp_FffozmdlxArjDyPFuaK-HMqK6D7u'
TXT_TEMPLATE_URL = 'https://drive.google.com/uc?export=download&id=1c4oGgR-T8KwlYbva_eR_0powWip8Lw5n'

def split_flag(flag):
    """Split flag into three roughly equal parts"""
    length = len(flag)
    part1_end = math.ceil(length / 3)
    part2_end = math.ceil(2 * length / 3)
    return [
        flag[:part1_end],
        flag[part1_end:part2_end],
        flag[part2_end:]
    ]

#procnet Challenge
procnet_challenge_id="68402692c6d6c84d40c70bc0"

#ai Challenge 
aiChallenge_id ="68414798c6d6c84d40c7247d"

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def proxy_login():
    try:
        data = request.json
        res = requests.post(
            f"{CTF_BASE_URL}/api/auth/login",
            json=data
        )
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": "Login failed", "details": str(e)}), 500

@app.route('/get_pcap', methods=['POST'])
def get_pcap():
    data = request.json
    token = data.get("token")

    if not token or not challenge_id:
        return jsonify({"error": "Missing token or challenge ID"}), 400

    try:
        headers = {
            "Auth-token": token
        }

        # Get the complete flag and username from Express
        flag_response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{challenge_id}",
            headers=headers
        )
        
        if flag_response.status_code != 200:
            return jsonify({"error": "Failed to get flag", "status": flag_response.status_code}), flag_response.status_code
        
        flag_data = flag_response.json()
        flag = flag_data['flag']
        username = flag_data['username']

        # Split the flag into parts
        flag_parts = split_flag(flag)

        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        
        # File paths
        original_pcap = os.path.join(temp_dir, 'original.pcap')
        modified_pcap = os.path.join(temp_dir, f'{username}.pcap')
        txt_file = os.path.join(temp_dir, f'{username}.txt')
        zip_file = os.path.join(temp_dir, 'challenge.zip')

        # Download PCAP
        pcap_response = requests.get(PCAP_DRIVE_URL)
        with open(original_pcap, 'wb') as f:
            f.write(pcap_response.content)

        # Modify PCAP with editcap
        subprocess.run([
            EDITCAP_PATH,
            '-a', f'2:{flag_parts[0]}',  # First part in packet 2
            '-a', f'5:{flag_parts[1]}',  # Second part in packet 5
            '-a', f'6:{flag_parts[2]}',  # Third part in packet 6
            original_pcap,
            modified_pcap
        ], check=True)

        # Download TXT template
        txt_response = requests.get(TXT_TEMPLATE_URL)
        with open(txt_file, 'wb') as f:
            f.write(txt_response.content)

        # Create ZIP using zipfile
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(modified_pcap, arcname=f'{username}.pcap')
            zipf.write(txt_file, arcname=f'{username}.txt')

        # Stream the ZIP file
        def generate():
            with open(zip_file, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            # Clean up
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="challenge_{username}.zip"'
            }
        )

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "PCAP processing failed", "details": str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Something went wrong", "details": str(e)}), 500
    
@app.route('/pcapdeepdive', methods=['POST'])
def pcap_deep_dive():
    data = request.json
    token = data.get("token")

    if not token :
        return jsonify({"error": "Missing token "}), 400

    try:
        # Step 1: Get the flag and username
        headers = {"Auth-token": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{deepDivechallenge_id}",
            headers=headers
        )
        if response.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), response.status_code

        flag_data = response.json()
        flag = flag_data['flag']
        username = flag_data['username']

        # Step 2: Read the Excel and get the corresponding URL
        df = pd.read_excel(EXCEL_PATH, header=None)
        match = df[df[0] == flag]
        if match.empty:
            return jsonify({"error": "Flag not found in Excel sheet"}), 404

        replacement_url = match.iloc[0, 2].encode()

        # Step 3: Create temp directory and modify PCAP
        temp_dir = tempfile.mkdtemp()
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        zip_path = os.path.join(temp_dir, f"{username}.zip")

        packets = rdpcap(ORIGINAL_PCAP_PATH)
        target_index = -1

        for i, pkt in enumerate(packets):
            if Raw in pkt and ORIGINAL_URL in pkt[Raw].load:
                target_index = i
                original_payload = pkt[Raw].load
                modified_payload = original_payload.replace(ORIGINAL_URL, replacement_url)
                pkt[Raw].load = modified_payload
                break

        if target_index == -1:
            shutil.rmtree(temp_dir)
            return jsonify({"error": "No packet found with the specified URL"}), 404

        wrpcap(output_pcap, packets)

        # Step 4: Zip and stream
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_pcap, arcname=f"{username}.pcap")

        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{username}.zip"'}
        )

    except Exception as e:
        return jsonify({"error": "Processing failed", "details": str(e)}), 500
    

@app.route('/chatgptchallenge', methods=['POST'])
def chatgpt_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Fetch flag and username
        headers = { "Auth-token": token }
        res = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{chatgpt_challenge_id}", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), res.status_code

        res_data = res.json()
        flag = res_data["flag"]
        username = res_data["username"]

        # Split flag into 6 parts
        flag_parts = split_flag_into_6_parts(flag)

        # Read original JS
        with open(INPUT_JS_PATH, "r", encoding="utf-8") as f:
            js_code = f.read()

        # Replace all parts
        for placeholder, index in PLACEHOLDER_MAP.items():
            if placeholder in js_code:
                js_code = js_code.replace(placeholder, flag_parts[index])
            else:
                print(f"⚠ Warning: Placeholder '{placeholder}' not found in JS")

        # Create temp folder and output
        temp_dir = tempfile.mkdtemp()
        output_js_path = os.path.join(temp_dir, f"{username}.js")
        zip_path = os.path.join(temp_dir, f"{username}_challenge.zip")

        # Write modified JS
        with open(output_js_path, "w", encoding="utf-8") as f:
            f.write(js_code)

        # Zip it
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_js_path, arcname=f"{username}.js")
            zipf.write(INPUT_JSON_PATH, arcname=f"{username}.json")

        # Stream response
        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{username}_challenge.zip"'}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/procnetchallenge', methods=['POST'])
def procnet_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        headers = {"Auth-token": token}

        # Fetch flag and username
        flag_response = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{procnet_challenge_id}", headers=headers)
        if flag_response.status_code != 200:
            return jsonify({"error": "Failed to fetch flag"}), flag_response.status_code

        flag_data = flag_response.json()
        flag_full = flag_data['flag']  # e.g., FLAG{abc_xyz}
        username = flag_data['username']

        userflag = flag_full.split('{')[1].split('_')[0]  # extract 'abc' from 'FLAG{abc_xyz}'
        new_session_id = f"{userflag}"

        # Set up paths
        temp_dir = tempfile.mkdtemp()
        input_pcap = os.path.join(temp_dir, "Employee_edited.pcap")
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        zip_file = os.path.join(temp_dir, 'challenge.zip')

        # Copy original PCAP from static folder
        shutil.copy("./Employee_edited.pcap", input_pcap)

        # Modify the pcap
        from scapy.all import rdpcap, wrpcap, IP, TCP, Raw

        packets = rdpcap(input_pcap)
        modified_packets = packets[:]
        TARGET_PACKET_NUMBER = 18487
        SRC_IP = "8.71.0.169"
        DST_IP = "6.92.79.1"

        def is_tls_client_hello(payload):
            return payload.startswith(b'\x16\x03') and payload[5] == 0x01

        for i, pkt in enumerate(packets):
            if i != TARGET_PACKET_NUMBER - 1:
                continue

            if IP in pkt and pkt[IP].src == SRC_IP and pkt[IP].dst == DST_IP and TCP in pkt and pkt[TCP].dport != 8080:
                if Raw in pkt:
                    payload = pkt[Raw].load
                    if is_tls_client_hello(payload):
                        sid_len_offset = 43
                        sid_len = payload[sid_len_offset]
                        sid_start = sid_len_offset + 1
                        sid_end = sid_start + sid_len

                        new_sid_bytes = new_session_id.encode('utf-8')
                        padded_sid = new_sid_bytes.ljust(sid_len, b'\x00')[:sid_len]

                        modified_payload = payload[:sid_start] + padded_sid + payload[sid_end:]
                        modified_packets[i][Raw].load = modified_payload
                        break

        wrpcap(output_pcap, modified_packets)

        # Zip it
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_pcap, arcname=f'{username}.pcap')

        def generate():
            with open(zip_file, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="challenge_{username}.zip"'}
        )

    except Exception as e:
        return jsonify({"error": "Processing failed", "details": str(e)}), 500


@app.route('/aichallenge', methods=['POST'])
def ai_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        # Step 1: Get the flag and username
        headers = {"Auth-token": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{aiChallenge_id}",
            headers=headers
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), response.status_code

        flag_data = response.json()
        flag = flag_data['flag']  # Example: flag{employee_records_e4c9046d}
        username = flag_data['username']

        # Step 2: Extract dynamic flag
        try:
            dynamic_flag = flag.split("employee_records_")[1].rstrip("}")
        except Exception:
            return jsonify({"error": "Invalid flag format"}), 400

        # Step 3: Create temp directory
        temp_dir = tempfile.mkdtemp()
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        zip_path = os.path.join(temp_dir, f"{username}.zip")

        # Step 4: Generate DNS packets
        def encode_data_to_subdomains(data, dynamic_flag):
            full_payload = f"{data}_{dynamic_flag}"
            encoded = base64.b32encode(full_payload.encode()).decode().rstrip('=')
            chunks = [encoded[i:i+8].ljust(8, '=') for i in range(0, len(encoded), 8)]
            return chunks

        def generate_legit_dns(start_time, hours=24):
            packets = []
            current_time = start_time
            domains = [
                "office365.com", "microsoft.com", "windows.com", "azure.com",
                "amazonaws.com", "github.com", "stackoverflow.com", "google.com",
                "linkedin.com", "slack.com", "zoom.us", "teams.microsoft.com"
            ]
            dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
            for hour in range(hours):
                for _ in range(random.randint(20, 40)):
                    domain = random.choice(domains)
                    server = random.choice(dns_servers)
                    pkt = IP(src="10.30.50.125", dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                    packets.append(pkt)
                current_time += timedelta(hours=1)
            return packets

        def generate_malicious_dns(start_time, dynamic_flag):
            exfil_data = "employee_records"
            chunks = encode_data_to_subdomains(exfil_data, dynamic_flag)
            exfil_start = start_time + timedelta(hours=6)
            dns_servers = ["8.8.8.8", "1.1.1.1"]
            packets = []

            for i, chunk in enumerate(chunks):
                malicious_domain = f"{chunk.lower()}.sys-inventory.cloudops.net"
                time_offset = exfil_start + timedelta(seconds=i * 47)
                pkt = IP(src="10.30.50.125", dst=random.choice(dns_servers))/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=malicious_domain))
                pkt.time = time_offset.timestamp()
                packets.append(pkt)

            # Noise
            for _ in range(3):
                noise_sub = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
                noise_domain = f"{noise_sub}.sys-inventory.cloudops.net"
                noise_time = exfil_start + timedelta(seconds=random.randint(1800, 2100))
                pkt = IP(src="10.30.50.125", dst=random.choice(dns_servers))/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=noise_domain))
                pkt.time = noise_time.timestamp()
                packets.append(pkt)

            return packets

        start_time = datetime(2024, 11, 15, 0, 0, 0)
        legit_dns = generate_legit_dns(start_time)
        malicious_dns = generate_malicious_dns(start_time, dynamic_flag)

        all_packets = legit_dns + malicious_dns
        all_packets.sort(key=lambda p: getattr(p, 'time', 0))
        wrpcap(output_pcap, all_packets)

        # Step 5: Copy logs
        shutil.copy("ai_detection_log.json", os.path.join(temp_dir, "ai_detection_log.json"))
        shutil.copy("corporate_whitelist.txt", os.path.join(temp_dir, "corporate_whitelist.txt"))

        # Step 6: Zip
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_pcap, arcname=f"{username}.pcap")
            zipf.write(os.path.join(temp_dir, "ai_detection_log.json"), arcname="ai_detection_log.json")
            zipf.write(os.path.join(temp_dir, "corporate_whitelist.txt"), arcname="corporate_whitelist.txt")

        # Step 7: Stream
        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{username}.zip"'}
        )

    except Exception as e:
        return jsonify({"error": "Processing failed", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5002)