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
import openpyxl
from setup import LunarSleeperGenerator

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
ApiFootprint_id = "6846af839d3ac335c86a5f53" 
MalDoc_id="6846b1889d3ac335c86a60ba"
LemonDuck_id="6846b1889d3ac335c86a60ba"
Jsploit_id="6846b3569d3ac335c86a6197"
cloudTrail_id="6846b00b9d3ac335c86a5fc1"
TimeSeriesTrap_id="68503fd1e0ef870ef388898d"
BGP_id="6850406fe0ef870ef3888a11"
kubernetes_id="685000cbe0ef870ef3887a71"


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
    },
     'ApiFootprint':{
        'json_file': os.path.join(CHALLENGES_DIR, 'ApiFootprint', 'api_gateway_logs_with_jwt.json'),
        },
    'MalDoc':{
        'xlsm_file': os.path.join(CHALLENGES_DIR, 'MalDoc', 'Q4_Sales_Report_2024.xlsm'),
    },
    'LemonDuck':{
        'LemonDuck1': os.path.join(CHALLENGES_DIR, 'LemonDuck', 'LemonDuck1.xlsm'),
        'LemonDuck2': os.path.join(CHALLENGES_DIR, 'LemonDuck', 'LemonDuck2.xlsm'),
        'LemonDuck3': os.path.join(CHALLENGES_DIR, 'LemonDuck', 'LemonDuck3.xlsm'),
        'LemonDuck4': os.path.join(CHALLENGES_DIR, 'LemonDuck', 'LemonDuck4.xlsm'),
        'LemonDuck5': os.path.join(CHALLENGES_DIR, 'LemonDuck', 'LemonDuck5.xlsm'),
    },
    'userIds':{
        'userId_file': os.path.join(CHALLENGES_DIR, 'userIds', 'userId.json'),
    },
    'Jsploit':{
        'Jsploit1': os.path.join(CHALLENGES_DIR, 'Jsploit', 'JSploit1.7z'),
        'Jsploit2': os.path.join(CHALLENGES_DIR, 'Jsploit', 'JSploit2.7z'),
        'Jsploit3': os.path.join(CHALLENGES_DIR, 'Jsploit', 'JSploit3.7z'),
        'Jsploit4': os.path.join(CHALLENGES_DIR, 'Jsploit', 'JSploit4.7z'),
        'Jsploit5': os.path.join(CHALLENGES_DIR, 'Jsploit', 'JSploit5.7z'),
    },
      'splitFiction':{
        'splitFiction1': os.path.join(CHALLENGES_DIR, 'splitFiction', 'splitFiction1.zip'),
        'splitFiction2': os.path.join(CHALLENGES_DIR, 'splitFiction', 'splitFiction2.zip'),
        'splitFiction3': os.path.join(CHALLENGES_DIR, 'splitFiction', 'splitFiction3.zip'),
        'splitFiction4': os.path.join(CHALLENGES_DIR, 'splitFiction', 'splitFiction4.zip'),
        'splitFiction5': os.path.join(CHALLENGES_DIR, 'splitFiction', 'splitFiction5.zip'),
    },
     'EncryptedLogForensics':{
        'system_logs1': os.path.join(CHALLENGES_DIR, 'EncryptedLogForensics', 'system_logs1.img'),
        'system_logs2': os.path.join(CHALLENGES_DIR, 'EncryptedLogForensics', 'system_logs2.img'),
        'system_logs3': os.path.join(CHALLENGES_DIR, 'EncryptedLogForensics', 'system_logs3.img'),
        'system_logs4': os.path.join(CHALLENGES_DIR, 'EncryptedLogForensics', 'system_logs4.img'),
        'system_logs5': os.path.join(CHALLENGES_DIR, 'EncryptedLogForensics', 'system_logs5.img'),
    },
      'BGP': {
        'txt_file_path': os.path.join(CHALLENGES_DIR, 'BGP', 'bgp_dump.txt'),
        'log_file_path': os.path.join(CHALLENGES_DIR, 'BGP', 'monitor_syslog.log'),
        'csv_file_path': os.path.join(CHALLENGES_DIR, 'BGP', 'netflow_logs.csv')
    },
    'MQTT':{
        'MQTT1': os.path.join(CHALLENGES_DIR, 'MQTT', 'MQTT1.pcap'),
        'MQTT2': os.path.join(CHALLENGES_DIR, 'MQTT', 'MQTT2.pcap'),
        'MQTT3': os.path.join(CHALLENGES_DIR, 'MQTT', 'MQTT3.pcap'),
        'MQTT4': os.path.join(CHALLENGES_DIR, 'MQTT', 'MQTT4.pcap'),
        'MQTT5': os.path.join(CHALLENGES_DIR, 'MQTT', 'MQTT5.pcap'),
        'json_file':os.path.join(CHALLENGES_DIR, 'MQTT', 'sensor_data.json'),
    },
      'deepDive':{
        'deepDive1': os.path.join(CHALLENGES_DIR, 'deepDive', 'deepDive1.pcap'),
        'deepDive2': os.path.join(CHALLENGES_DIR, 'deepDive', 'deepDive2.pcap'),
        'deepDive3': os.path.join(CHALLENGES_DIR, 'deepDive', 'deepDive3.pcap'),
        'deepDive4': os.path.join(CHALLENGES_DIR, 'deepDive', 'deepDive4.pcap'),
        'deepDive5': os.path.join(CHALLENGES_DIR, 'deepDive', 'deepDive5.pcap'),
    
    },
    'kubernetes':{
        'yaml_file' : os.path.join(CHALLENGES_DIR, 'kubernetes', 'deployment.yaml'),
        'docker_file' : os.path.join(CHALLENGES_DIR, 'kubernetes', 'Dockerfile'),
        'dump_json_file' : os.path.join(CHALLENGES_DIR, 'kubernetes', 'etcd_dump.json'),
        'sh_file' : os.path.join(CHALLENGES_DIR, 'kubernetes', 'ghost-init.sh'),
        'log_file' : os.path.join(CHALLENGES_DIR, 'kubernetes', 'journal.log'),
        'network_json_file' : os.path.join(CHALLENGES_DIR, 'kubernetes', 'network-logs.json'),
    },
    'ShadowInCiMassive':{
        'ShadowInCiMassive1': os.path.join(CHALLENGES_DIR, 'ShadowInCiMassive', 'ShadowInCiMassive1.zip'),
        'ShadowInCiMassive2': os.path.join(CHALLENGES_DIR, 'ShadowInCiMassive', 'ShadowInCiMassive2.zip'),
        'ShadowInCiMassive3': os.path.join(CHALLENGES_DIR, 'ShadowInCiMassive', 'ShadowInCiMassive3.zip'),
        'ShadowInCiMassive4': os.path.join(CHALLENGES_DIR, 'ShadowInCiMassive', 'ShadowInCiMassive4.zip'),
        'ShadowInCiMassive5': os.path.join(CHALLENGES_DIR, 'ShadowInCiMassive', 'ShadowInCiMassive5.zip'),
    },
       'BeaconInTheDark':{
        'BeaconInTheDark1': os.path.join(CHALLENGES_DIR, 'BeaconInTheDark', 'BeaconInTheDark1.zip'),
        'BeaconInTheDark2': os.path.join(CHALLENGES_DIR, 'BeaconInTheDark', 'BeaconInTheDark2.zip'),
        'BeaconInTheDark3': os.path.join(CHALLENGES_DIR, 'BeaconInTheDark', 'BeaconInTheDark3.zip'),
        'BeaconInTheDark4': os.path.join(CHALLENGES_DIR, 'BeaconInTheDark', 'BeaconInTheDark4.zip'),
        'BeaconInTheDark5': os.path.join(CHALLENGES_DIR, 'BeaconInTheDark', 'BeaconInTheDark5.zip'),
    }
}

# Common functions


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
def pcapdeepdive_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get user info from auth endpoint - using POST request
        headers = { "Auth-token": token }
        res = requests.post(f"{CTF_BASE_URL}/api/auth/getuser", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get user info", "status_code": res.status_code}), res.status_code

        user_data = res.json()
        user_id = user_data["_id"]
        username = user_data["name"]

        # Load the userId.json file from configured path
        userid_path = CHALLENGE_PATHS['userIds']['userId_file']
        with open(userid_path, 'r') as f:
            teams = json.load(f)
        
        # Find the matching team by ID
        team = next((t for t in teams if t["id"] == user_id), None)
        if not team:
            return jsonify({"error": "User ID not found in teams"}), 404
        
        team_index = team["index"]
        
        # Determine which pcap file to use (cycle through 1-5)
        pcap_number = ((team_index - 1) % 5) + 1
       
        pcap_filename = f"deepDive{pcap_number}.pcap"
        pcap_path = CHALLENGE_PATHS['deepDive'][f"deepDive{pcap_number}"]
       
        
        if not os.path.exists(pcap_path):
            return jsonify({"error": f"PCAP file {pcap_filename} not found"}), 404
        
        # Create a temp directory for processing
        temp_dir = tempfile.mkdtemp()
        output_filename = f"{username}.pcap"
        output_path = os.path.join(temp_dir, output_filename)
        zip_path = os.path.join(temp_dir, f"{username}_pcapdeepdive.zip")
        
        # Copy the file with new name
        shutil.copy(pcap_path, output_path)
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_path, arcname=output_filename)
        
        # Stream the response and clean up
        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)
        
        return Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="{username}_pcapdeepdive.zip"',
                'Content-Type': 'application/zip'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# @app.route('/pcapdeepdive', methods=['POST'])
# def pcap_deep_dive():
#     data = request.json
#     token = data.get("token")

#     if not token:
#         return jsonify({"error": "Missing token"}), 400

#     try:
#         headers = {"Auth-token": token}
#         response = requests.get(
#             f"{CTF_BASE_URL}/api/challenges/get-flag/{deepDivechallenge_id}",
#             headers=headers
#         )
#         if response.status_code != 200:
#             return jsonify({"error": "Failed to get flag"}), response.status_code

#         flag_data = response.json()
#         flag = flag_data['flag']
#         username = flag_data['username']

#         df = pd.read_excel(CHALLENGE_PATHS['pcapdeepdive']['excel_path'], header=None)
#         match = df[df[0] == flag]
#         if match.empty:
#             return jsonify({"error": "Flag not found in Excel sheet"}), 404

#         replacement_url = match.iloc[0, 2].encode()
#         temp_dir = tempfile.mkdtemp()
#         output_pcap = os.path.join(temp_dir, f"{username}.pcap")
#         zip_path = os.path.join(temp_dir, f"{username}.zip")

#         packets = rdpcap(CHALLENGE_PATHS['pcapdeepdive']['pcap_path'])
#         target_index = -1

#         for i, pkt in enumerate(packets):
#             if Raw in pkt and CHALLENGE_PATHS['pcapdeepdive']['original_url'] in pkt[Raw].load:
#                 target_index = i
#                 original_payload = pkt[Raw].load
#                 modified_payload = original_payload.replace(
#                     CHALLENGE_PATHS['pcapdeepdive']['original_url'], 
#                     replacement_url
#                 )
#                 pkt[Raw].load = modified_payload
#                 break

#         if target_index == -1:
#             shutil.rmtree(temp_dir)
#             return jsonify({"error": "No packet found with the specified URL"}), 404

#         wrpcap(output_pcap, packets)

#         with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
#             zipf.write(output_pcap, arcname=f"{username}.pcap")

#         def generate():
#             with open(zip_path, 'rb') as f:
#                 while chunk := f.read(1024):
#                     yield chunk
#             shutil.rmtree(temp_dir)

#         return Response(
#             generate(),
#             mimetype='application/zip',
#             headers={'Content-Disposition': f'attachment; filename="{username}.zip"'}
#         )

#     except Exception as e:
#         return jsonify({"error": "Processing failed", "details": str(e)}), 500

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
        
        # Extract the part after the last underscore (before closing })
        if '_' not in flag or not flag.endswith('}'):
            return jsonify({"error": "Invalid flag format"}), 400
        
        # Split into parts: FLAG{prefix_random} → ["FLAG{prefix", "random}"]
        # Then take the last part, remove the trailing '}'
        random_part = flag.split('_')[-1].rstrip('}')

        with open(CHALLENGE_PATHS['chatgpt']['js_path'], "r", encoding="utf-8") as f:
            js_code = f.read()

        # Replace "drop" with the extracted random part
        js_code = js_code.replace("drop", random_part)

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
                print(chunk.lower())
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

        # Focus only on packet 134326 (index 134325 in zero-based)
        pkt = packets[134325]
        if not pkt.haslayer(Raw):
            return jsonify({"error": "Target packet has no payload"}), 400

        payload = pkt[Raw].load
        target = b'secret+files+api+key=098ABCD12345!\n'
        
        if target not in payload:
            return jsonify({"error": "Target string not found in packet"}), 400

        # Replace target with part_b
        modified_payload = payload.replace(
            target,
            b'secret+files+api+key=' + part_b.encode() + b'\n'
        )
        
        # Update Content-Length if present
        if b'Content-Length:' in modified_payload:
            import re
            modified_payload = re.sub(
                b'Content-Length: \\d+',
                b'Content-Length: ' + str(len(part_b)).encode(),
                modified_payload
            )

        pkt[Raw].load = modified_payload
        del pkt[IP].len, pkt[IP].chksum, pkt[TCP].chksum

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
        return jsonify({"error": "Processing failed", "details": str(e)}), 500

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
        
        # Create the modified JSP with part_b inserted
        jsp_template = """<<%@% page import=\"java.io.\" %>
%>
    String cmd = request.getParameter( \"cmd\" );

    out.println(\"<h3>JSP Web Shell by APT12 from Area {part_b}</h3>\");
    out.println(\"<form method='GET'>\");
    out.println(\"Command: <input type='text' name='cmd'> <input type=\"submit\" value=\"Execute\"></form>\");

    if (cmd != null) {
        out.println(\"<pre>\");
        out.println("Simulated command output for: " + cmd);
        out.println(\"[*] command executed.\");
        out.println(\"*] namedpandaapt12H4xor1\\");
        out.println(\"</pre>\");
    }
%>""".replace("{part_b}", part_b)

        # Base64 encode the JSP
        import base64
        modified_jsp_b64 = base64.b64encode(jsp_template.encode()).decode()

        packets = rdpcap(CHALLENGE_PATHS['SpringBoot']['pcap_path'])

        # Modify packet 125814 (frame index = 125813)
        pkt_b = packets[125813]
        found_b = False
        if pkt_b.haslayer(Raw):
            payload = pkt_b[Raw].load
            target = b'PDwlQCUgcGFnZSBpbXBvcnQ9XCJqYXZhLmlvLlwiICU+DQolPg0KICAgIFN0cmluZyBjbWQgPSByZXF1ZXN0LmdldFBhcmFtZXRlciggXCJjbWRcIiApOw0KDQogICAgb3V0LnByaW50bG4oXCI8aDM+SlNQIFdlYiBTaGVsbCBieSBBUFQxMjwvaDM+XCIpOw0KICAgIG91dC5wcmludGxuKFwiPGZvcm0gbWV0aG9kPSdHRVQnPlwiKTsNCiAgICBvdXQucHJpbnRsbihcIkNvbW1hbmQ6IDxpbnB1dCB0eXBlPSd0ZXh0JyBuYW1lPSdjbWQnPiA8aW5wdXQgdHlwZT1cInN1Ym1pdFwiIHZhbHVlPVwiRXhlY3V0ZVwiPjwvZm9ybT5cIik7DQoNCiAgICBpZiAoY21kICE9IG51bGwpIHsNCiAgICAgICAgb3V0LnByaW50bG4oXCI8cHJlPlwiKTsNCiAgICAgICAgb3V0LnByaW50bG4oIlNpbXVsYXRlZCBjb21tYW5kIG91dHB1dCBmb3I6ICIgKyBjbWQpOw0KICAgICAgICBvdXQucHJpbnRsbihcIlsqXSBjb21tYW5kIGV4ZWN1dGVkLlwiKTsNCiAgICAgICAgb3V0LnByaW50bG4oXCIqXSBuYW1lZHBhbmRhYXB0MTJINHhvcjFcXCIpOw0KICAgICAgICBvdXQucHJpbnRsbihcIjwvcHJlPlwiKTsNCiAgICB9DQolPg=='
            
            if target in payload:
                new_payload = payload.replace(
                    target,
                    modified_jsp_b64.encode()
                )
                pkt_b[Raw].load = new_payload
                del pkt_b[IP].len, pkt_b[IP].chksum, pkt_b[TCP].chksum
                found_b = True

        if not found_b:
            return jsonify({"error": "Target packet not modified"}), 400

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
        return jsonify({"error": "Processing failed", "details": str(e)}), 500

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
            if entry.get("host") == "LIN-Sys1em":
                entry["hostName"] = part_a

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

@app.route('/ApiFootprint', methods=['POST'])
def api_footprint_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get flag from CTF backend
        headers = {"Auth-token": token}
        res = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{ApiFootprint_id}", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), res.status_code

        res_data = res.json()
        flag = res_data["flag"]
        username = res_data["username"]

        # Step 1: Extract 'user_id' from the flag
        # Format: CTF{2024-01-15_14:26:34_/admin/users_GET_1332}
        user_id_str = flag.rsplit("_", 1)[-1].rstrip("}")
        new_user_id = int(user_id_str)

        # Step 2: Prepare new JSON payload and encode it
        new_user_data = {
            "user_id": new_user_id,
            "username": "emma.wilson",
            "role": "admin",
            "department": "IT",
            "exp": 1749145607,
            "iat": 1749142007,
            "iss": "techcorp-auth"
        }
        new_b64 = base64.b64encode(json.dumps(new_user_data).encode("utf-8")).decode("utf-8")

        # Step 3: Load the original file and replace the old encoded string
        with open(CHALLENGE_PATHS['ApiFootprint']['json_file'], 'r', encoding='utf-8') as f:
            file_content = f.read()

        
        old_b64 = "eyJ1c2VyX2lkIjogODI0MCwgInVzZXJuYW1lIjogImVtbWEud2lsc29uIiwgInJvbGUiOiAiYWRtaW4iLCAiZGVwYXJ0bWVudCI6ICJJVCIsICJleHAiOiAxNzQ5MTQ1NjA3LCAiaWF0IjogMTc0OTE0MjAwNywgImlzcyI6ICJ0ZWNoY29ycC1hdXRoIn0"
        updated_content = file_content.replace(old_b64, new_b64)

        # Step 4: Create temp dir, write updated file
        temp_dir = tempfile.mkdtemp()
        output_json_path = os.path.join(temp_dir, f"{username}.json")
        zip_path = os.path.join(temp_dir, f"{username}_challenge.zip")

        with open(output_json_path, "w", encoding="utf-8") as f:
            f.write(updated_content)

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_json_path, arcname=f"{username}.json")

        # Step 5: Stream zipped response
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


def flag_to_lsb_encoded_numbers(flag, total_numbers=248, flag_position='start'):
    """
    Encode a flag into numbers using LSB steganography with padding
    
    Args:
        flag (str): The flag to encode
        total_numbers (int): Total numbers to generate
        flag_position (str): Where to place flag - 'start', 'end', or 'middle'
    
    Returns:
        tuple: (encoded_numbers_list, flag_start_index, flag_end_index)
    """
    # Convert flag to binary
    binary_string = ""
    for char in flag:
        binary_char = format(ord(char), '08b')
        binary_string += binary_char
    
    # Calculate padding needed
    flag_bits_needed = len(binary_string)
    padding_bits = total_numbers - flag_bits_needed
    
    if padding_bits < 0:
        raise ValueError(f"Flag too long! Need {flag_bits_needed} bits but only have {total_numbers} positions")
    
    # Determine flag placement
    if flag_position == 'start':
        flag_start = 0
        flag_end = flag_bits_needed
    elif flag_position == 'end':
        flag_start = padding_bits
        flag_end = total_numbers
    elif flag_position == 'middle':
        padding_before = padding_bits // 2
        flag_start = padding_before
        flag_end = flag_start + flag_bits_needed
    else:
        flag_start = 0
        flag_end = flag_bits_needed
    
    # Generate complete bit sequence
    complete_bits = ['0'] * total_numbers
    
    # Insert flag bits at the specified position
    for i, bit in enumerate(binary_string):
        complete_bits[flag_start + i] = bit
    
    # Randomize the padding bits
    for i in range(total_numbers):
        if i < flag_start or i >= flag_end:
            complete_bits[i] = str(random.randint(0, 1))
    
    # Generate numbers with specific LSBs
    encoded_numbers = []
    
    for bit in complete_bits:
        base_number = random.randint(25, 250) * 2  # Even number first
        number = base_number + 1 if bit == '1' and base_number % 2 == 0 else base_number
        number = base_number - 1 if bit == '0' and base_number % 2 == 1 else number
        encoded_numbers.append(number)
    
    return encoded_numbers, flag_start, flag_end

def update_excel_file(numbers, input_file, output_file):
    """Update the Excel file with the encoded numbers in the Units_Sold column"""
    try:
        # Load the workbook
        wb = openpyxl.load_workbook(input_file, keep_vba=True)
        
        # Check if sales_data sheet exists
        if 'Sales_data' not in wb.sheetnames:
            raise ValueError("'Sales_data' sheet not found in the workbook")
        
        sheet = wb['Sales_data']
        
        # Store original sheet visibility state
        was_hidden = sheet.sheet_state == 'hidden'
        
        # Unhide the sheet if it's hidden
        if was_hidden:
            sheet.sheet_state = 'visible'
        
        # Find the Units_Sold column
        units_sold_col = None
        for col in range(1, 10):  # Check first 10 columns
            if sheet.cell(row=1, column=col).value == "Units_Sold":
                units_sold_col = col
                break
        
        if units_sold_col is None:
            raise ValueError("'Units_Sold' column not found in the sheet")
        
        # Update the values (rows 2 to 249)
        for i in range(len(numbers)):
            sheet.cell(row=i+2, column=units_sold_col, value=numbers[i])
        
        # Restore original hidden state if it was hidden
        if was_hidden:
            sheet.sheet_state = 'hidden'
        
        # Save the modified workbook
        wb.save(output_file)
        return True
        
    except Exception as e:
        print(f"Error updating Excel file: {str(e)}")
        return False
   
@app.route('/maldocchallenge', methods=['POST'])
def maldoc_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get flag from CTF platform
        headers = {"Auth-token": token}
        res = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{MalDoc_id}", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), res.status_code

        res_data = res.json()
        flag = res_data["flag"]
        username = res_data["username"]

        # Encode the flag into numbers using LSB steganography
        encoded_numbers, flag_start, flag_end = flag_to_lsb_encoded_numbers(
            flag, 
            total_numbers=248,
            flag_position='start'
        )

        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        original_xlsm = CHALLENGE_PATHS['MalDoc']['xlsm_file']
        output_xlsm = os.path.join(temp_dir, f"Q4_Sales_Report_2024_{username}.xlsm")
        zip_path = os.path.join(temp_dir, f"{username}_maldoc_challenge.zip")

        # Update the Excel file with encoded numbers
        success = update_excel_file(
            encoded_numbers,
            input_file=original_xlsm,
            output_file=output_xlsm
        )

        if not success:
            raise Exception("Failed to encode flag into Excel file")

        # Create zip file with the modified Excel
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_xlsm, arcname=f"Q4_Sales_Report_2024_{username}.xlsm")

        # Stream the response
        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            # Clean up
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{username}_maldoc_challenge.zip"'}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/lemondock', methods=['POST'])
def lemondock_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get user info from auth endpoint - using POST request
        headers = { "Auth-token": token }
        res = requests.post(f"{CTF_BASE_URL}/api/auth/getuser", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get user info", "status_code": res.status_code}), res.status_code

        user_data = res.json()
        user_id = user_data["_id"]
        username = user_data["name"]

        # Load the userId.json file from configured path
        userid_path = CHALLENGE_PATHS['userIds']['userId_file']
        with open(userid_path, 'r') as f:
            teams = json.load(f)
        
        # Find the matching team by ID
        team = next((t for t in teams if t["id"] == user_id), None)
        if not team:
            return jsonify({"error": "User ID not found in teams"}), 404
        
        team_index = team["index"]
        
        # Determine which LemonDuck file to use (cycle through 1-5)
        lemon_duck_number = ((team_index - 1) % 5) + 1
        lemon_duck_filename = f"LemonDuck{lemon_duck_number}.xlsm"
        lemon_duck_path = CHALLENGE_PATHS['LemonDuck'][f"LemonDuck{lemon_duck_number}"]
        
        if not os.path.exists(lemon_duck_path):
            return jsonify({"error": f"LemonDuck file {lemon_duck_filename} not found"}), 404
        
        # Create a temp directory for processing
        temp_dir = tempfile.mkdtemp()
        output_filename = f"{username}.xlsm"
        output_path = os.path.join(temp_dir, output_filename)
        zip_path = os.path.join(temp_dir, f"{username}_lemondock.zip")
        
        # Copy the file with new name
        shutil.copy(lemon_duck_path, output_path)
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_path, arcname=output_filename)
        
        # Stream the response and clean up
        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)
        
        return Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="{username}_lemondock.zip"',
                'Content-Type': 'application/zip'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# @app.route('/jsploit', methods=['POST'])
# def jsploit_challenge():
#     data = request.json
#     token = data.get("token")

#     if not token:
#         return jsonify({"error": "Missing token"}), 400

#     try:
#         headers = {"Auth-token": token}
#         response = requests.get(
#             f"{CTF_BASE_URL}/api/challenges/get-flag/{Jsploit_id}",
#             headers=headers
#         )

#         if response.status_code != 200:
#             return jsonify({"error": "Failed to get flag"}), response.status_code

#         flag_data = response.json()
#         flag = flag_data['flag']
#         username = flag_data['username']

#         if not flag.startswith("FLAG{") or not flag.endswith("}"):
#             return jsonify({"error": "Invalid flag format"}), 400

#         flag_content = flag[5:-1]  # Extract content between curly braces

#         # Load the pcapng file
#         pcapng_path = CHALLENGE_PATHS['Jsploit']['pcapng_file']
#         packets = rdpcap(pcapng_path)

#         # Modify packet 3013657 (frame index = 3013656)
#         if len(packets) <= 3013656:
#             return jsonify({"error": "Packet index out of range"}), 400

#         pkt = packets[3013656]
#         found = False
        
#         if pkt.haslayer(TCP) and pkt.haslayer(Raw):
#             payload = pkt[Raw].load
#             target = b'XXXXX/App.js'
#             if target in payload:
#                 new_payload = payload.replace(
#                     target,
#                     f"{flag_content}/App.js".encode()
#                 )
#                 pkt[Raw].load = new_payload
#                 # Recalculate checksums
#                 del pkt[IP].len, pkt[IP].chksum, pkt[TCP].chksum
#                 found = True

#         if not found:
#             return jsonify({"error": "Target packet not modified"}), 400

#         # Create zip
#         temp_dir = tempfile.mkdtemp()
#         output_pcapng = os.path.join(temp_dir, f"{username}.pcapng")
#         zip_path = os.path.join(temp_dir, f"{username}.zip")

#         wrpcap(output_pcapng, packets)

#         with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
#             zipf.write(output_pcapng, arcname=f"{username}.pcapng")

#         def generate():
#             with open(zip_path, 'rb') as f:
#                 while chunk := f.read(1024):
#                     yield chunk
#             shutil.rmtree(temp_dir)

#         return Response(
#             generate(),
#             mimetype='application/zip',
#             headers={'Content-Disposition': f'attachment; filename="{username}.zip"'}
#         )

#     except Exception as e:
#         return jsonify({"error": "Processing failed", "details": str(e)}), 500

@app.route('/jsploit', methods=['POST'])
def jsploit_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get user info from auth endpoint - using POST request
        headers = { "Auth-token": token }
        res = requests.post(f"{CTF_BASE_URL}/api/auth/getuser", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get user info", "status_code": res.status_code}), res.status_code

        user_data = res.json()
        user_id = user_data["_id"]
        username = user_data["name"]

        # Load the userId.json file from configured path
        userid_path = CHALLENGE_PATHS['userIds']['userId_file']
        with open(userid_path, 'r') as f:
            teams = json.load(f)
        
        # Find the matching team by ID
        team = next((t for t in teams if t["id"] == user_id), None)
        if not team:
            return jsonify({"error": "User ID not found in teams"}), 404
        
        team_index = team["index"]
        
        # Determine which Jsploit file to use (cycle through 1-5)
        jsploit_number = ((team_index - 1) % 5) + 1
        jsploit_filename = f"JSploit{jsploit_number}.7z"
        jsploit_path = CHALLENGE_PATHS['Jsploit'][f"Jsploit{jsploit_number}"]
        
        if not os.path.exists(jsploit_path):
            return jsonify({"error": f"Jsploit file {jsploit_filename} not found"}), 404
        
        # Stream the response directly
        def generate():
            with open(jsploit_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
        
        return Response(
            generate(),
            mimetype='application/x-7z-compressed',
            headers={
                'Content-Disposition': f'attachment; filename="{username}"',
                'Content-Type': 'application/x-7z-compressed'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/cloudTrail', methods=['POST'])
def cloud_trail_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get flag from CTF platform
        headers = {"Auth-token": token}
        res = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{cloudTrail_id}", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), res.status_code

        res_data = res.json()
        flag = res_data["flag"]
        username = res_data["username"]

        # Extract team name from flag (between 3rd and 4th underscore)
        # Flag format: FLAG{LUNAR_ECLIPSE_2024_blueteam34_23591173}
        try:
            flag_parts = flag.strip("FLAG{}").split('_')
            if len(flag_parts) >= 4:
                team_id = flag_parts[3]  # 4th part (0-indexed 3)
            else:
                team_id = username  # fallback to username if format doesn't match
        except Exception as e:
            team_id = username  # fallback to username if any error occurs

        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        output_json = os.path.join(temp_dir, f"lunar_sleeper_{team_id}.json")
        zip_path = os.path.join(temp_dir, f"{username}_cloudtrail_challenge.zip")

        # Generate the challenge data
        generator = LunarSleeperGenerator(team_id)
        challenge_data = generator.generate_complete_challenge()

        # Save to JSON file
        with open(output_json, 'w') as f:
            json.dump(challenge_data, f, indent=2)

        # Create zip file with the JSON
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_json, arcname=f"lunar_sleeper_{team_id}.json")

        # Stream the response
        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            # Clean up
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{username}_cloudtrail_challenge.zip"'}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/timeseriestrap', methods=['POST'])
def timeseries_trap():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        headers = { "Auth-token": token }
        res = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{TimeSeriesTrap_id}", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), res.status_code

        res_data = res.json()
        flag = res_data["flag"]
        username = res_data["username"]
        
        # Generate binary representation of the flag
        binary_flag = ''.join(format(ord(c), '08b') for c in flag)

        start_time = datetime(2024, 1, 1, 0, 0, 0)
        timestamps = [start_time]
        sensor_values = [round(random.uniform(20, 30), 2)]  # dummy values

        # Encode using time deltas
        for bit in binary_flag:
            last_time = timestamps[-1]
            delta = timedelta(seconds=5 if bit == '0' else 3)
            new_time = last_time + delta
            timestamps.append(new_time)
            sensor_values.append(round(random.uniform(20, 30), 2))

        # Create DataFrame
        df = pd.DataFrame({
            "timestamp": timestamps,
            "sensor_value": sensor_values
        })

        temp_dir = tempfile.mkdtemp()
        csv_path = os.path.join(temp_dir, f"sensor_logs_{username}.csv")
        zip_path = os.path.join(temp_dir, f"{username}_timeseries_challenge.zip")

        # Save to CSV
        df.to_csv(csv_path, index=False)

        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(csv_path, arcname=f"sensor_logs_{username}.csv")

        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{username}_timeseries_challenge.zip"'}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    


@app.route('/splitFiction', methods=['POST'])
def splitFiction_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get user info from auth endpoint - using POST request
        headers = { "Auth-token": token }
        res = requests.post(f"{CTF_BASE_URL}/api/auth/getuser", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get user info", "status_code": res.status_code}), res.status_code

        user_data = res.json()
        user_id = user_data["_id"]
        username = user_data["name"]

        # Load the userId.json file from configured path
        userid_path = CHALLENGE_PATHS['userIds']['userId_file']
        with open(userid_path, 'r') as f:
            teams = json.load(f)
        
        # Find the matching team by ID
        team = next((t for t in teams if t["id"] == user_id), None)
        if not team:
            return jsonify({"error": "User ID not found in teams"}), 404
        
        team_index = team["index"]
        
        # Determine which Jsploit file to use (cycle through 1-5)
        splitFiction_number = ((team_index - 1) % 5) + 1
        splitFiction_filename = f"splitFiction_{splitFiction_number}.zip"
        splitFiction_path = CHALLENGE_PATHS['splitFiction'][f"splitFiction{splitFiction_number}"]
        
        if not os.path.exists(splitFiction_path):
            return jsonify({"error": f"splitFiction file {splitFiction_filename} not found"}), 404
        
        # Stream the response directly
        def generate():
            with open(splitFiction_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
        
        return Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="{username}"',
                'Content-Type': 'application/zip'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/EncryptedLogForensics', methods=['POST'])
def encrypted_log_forensics_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get user info from auth endpoint - using POST request
        headers = { "Auth-token": token }
        res = requests.post(f"{CTF_BASE_URL}/api/auth/getuser", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get user info", "status_code": res.status_code}), res.status_code

        user_data = res.json()
        user_id = user_data["_id"]
        username = user_data["name"]

        # Load the userId.json file from configured path
        userid_path = CHALLENGE_PATHS['userIds']['userId_file']
        with open(userid_path, 'r') as f:
            teams = json.load(f)
        
        # Find the matching team by ID
        team = next((t for t in teams if t["id"] == user_id), None)
        if not team:
            return jsonify({"error": "User ID not found in teams"}), 404
        
        team_index = team["index"]
        
        # Determine which system logs file to use (cycle through 1-5)
        system_logs_number = ((team_index - 1) % 5) + 1
        system_logs_filename = f"system_logs{system_logs_number}.img"
        system_logs_path = CHALLENGE_PATHS['EncryptedLogForensics'][f"system_logs{system_logs_number}"]
        
        if not os.path.exists(system_logs_path):
            return jsonify({"error": f"System logs file {system_logs_filename} not found"}), 404
        
        # Create a temp directory for processing
        temp_dir = tempfile.mkdtemp()
        output_filename = f"system_logs_{username}.img"
        output_path = os.path.join(temp_dir, output_filename)
        zip_path = os.path.join(temp_dir, f"{username}_encrypted_logs.zip")
        
        # Copy the file with new name
        shutil.copy(system_logs_path, output_path)
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_path, arcname=output_filename)
        
        # Stream the response and clean up
        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)
        
        return Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="{username}_encrypted_logs.zip"',
                'Content-Type': 'application/zip'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/bgp', methods=['POST'])
def bgp_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        headers = {"Auth-token": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/challenges/get-flag/{BGP_id}",
            headers=headers
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), response.status_code

        flag_data = response.json()
        flag = flag_data['flag']
        username = flag_data['username']

        

        temp_dir = tempfile.mkdtemp()
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        zip_path = os.path.join(temp_dir, f"{username}.zip")

        # Parameters for BGP DNS exfiltration
        attacker_ip = "203.0.113.10"
        dns_server_ip = "1.1.1.1"

        # Encode and chunk the flag
        b64 = base64.b64encode(flag.encode()).decode()
        chunks = [b64[i:i+10] for i in range(0, len(b64), 10)]

        # Build DNS packets
        packets = []
        for i, chunk in enumerate(chunks):
            domain = f"exf{i}.{chunk}.shadowhydra.com"
            pkt = IP(src=attacker_ip, dst=dns_server_ip)/UDP(sport=12345+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
            packets.append(pkt)

        # Save the PCAP
        wrpcap(output_pcap, packets)

        # Copy the additional files from CHALLENGE_PATHS
        shutil.copy(CHALLENGE_PATHS['BGP']['txt_file_path'], os.path.join(temp_dir, "bgp_dump.txt"))
        shutil.copy(CHALLENGE_PATHS['BGP']['log_file_path'], os.path.join(temp_dir, "monitor_syslog.log"))
        shutil.copy(CHALLENGE_PATHS['BGP']['csv_file_path'], os.path.join(temp_dir, "netflow_logs.csv"))

        # Create the zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_pcap, arcname=f"{username}.pcap")
            zipf.write(os.path.join(temp_dir, "bgp_dump.txt"), arcname="bgp_dump.txt")
            zipf.write(os.path.join(temp_dir, "monitor_syslog.log"), arcname="monitor_syslog.log")
            zipf.write(os.path.join(temp_dir, "netflow_logs.csv"), arcname="netflow_logs.csv")

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

@app.route('/mqtt', methods=['POST'])
def mqtt_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get user info from auth endpoint - using POST request
        headers = { "Auth-token": token }
        res = requests.post(f"{CTF_BASE_URL}/api/auth/getuser", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get user info", "status_code": res.status_code}), res.status_code

        user_data = res.json()
        user_id = user_data["_id"]
        username = user_data["name"]

        # Load the userId.json file from configured path
        userid_path = CHALLENGE_PATHS['userIds']['userId_file']
        with open(userid_path, 'r') as f:
            teams = json.load(f)
        
        # Find the matching team by ID
        team = next((t for t in teams if t["id"] == user_id), None)
        if not team:
            return jsonify({"error": "User ID not found in teams"}), 404
        
        team_index = team["index"]
        
        # Determine which MQTT pcap file to use (cycle through 1-5)
        mqtt_number = ((team_index - 1) % 5) + 1
        mqtt_filename = f"MQTT{mqtt_number}.pcap"
        mqtt_path = CHALLENGE_PATHS['MQTT'][f"MQTT{mqtt_number}"]
        
        if not os.path.exists(mqtt_path):
            return jsonify({"error": f"MQTT pcap file {mqtt_filename} not found"}), 404
        
        # Get the JSON file path
        json_path = CHALLENGE_PATHS['MQTT']['json_file']
        if not os.path.exists(json_path):
            return jsonify({"error": "Sensor data JSON file not found"}), 404
        
        # Create a temp directory for processing
        temp_dir = tempfile.mkdtemp()
        output_pcap = os.path.join(temp_dir, f"{username}.pcap")
        output_json = os.path.join(temp_dir, "sensor_data.json")
        zip_path = os.path.join(temp_dir, f"{username}_mqtt_data.zip")
        
        # Copy the files with new names
        shutil.copy(mqtt_path, output_pcap)
        shutil.copy(json_path, output_json)
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_pcap, arcname=f"{username}.pcap")
            zipf.write(output_json, arcname="sensor_data.json")
        
        # Stream the response and clean up
        def generate():
            with open(zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)
        
        return Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="{username}_mqtt_data.zip"',
                'Content-Type': 'application/zip'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/kubernetes', methods=['POST'])
def kubernetes_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        headers = { "Auth-token": token }
        res = requests.get(f"{CTF_BASE_URL}/api/challenges/get-flag/{kubernetes_id}", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get flag"}), res.status_code

        res_data = res.json()
        flag = res_data["flag"]
        username = res_data["username"]
        
        # Generate the libhttpd.so.1.3 file with the embedded flag
        new_flag = flag
        container_name = "ghostsvc"
        xor_key = sum([ord(c) for c in container_name]) % 256
        encoded_flag = ''.join([chr(ord(c) ^ xor_key) for c in new_flag])
        binary_data = bytearray([random.randint(0, 255) for _ in range(800)])
        binary_data[400:400+len(encoded_flag)] = encoded_flag.encode()
        

        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        
        # Save the fake ELF binary
        libhttpd_path = os.path.join(temp_dir, "libhttpd.so.1.3")
        with open(libhttpd_path, "wb") as f:
            f.write(binary_data)

        # Create carany_image_build.zip with the three main files
        carany_zip_path = os.path.join(temp_dir, "carany_image_build.zip")
        with zipfile.ZipFile(carany_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add Dockerfile
            docker_path = CHALLENGE_PATHS['kubernetes']['docker_file']
            zipf.write(docker_path, arcname="Dockerfile")
            # Add eghost-init.sh
            sh_path = CHALLENGE_PATHS['kubernetes']['sh_file']
            zipf.write(sh_path, arcname="ghost-init.sh")
            # Add libhttpd.so.1.3
            zipf.write(libhttpd_path, arcname="libhttpd.so.1.3")

        # Copy other required files to temp directory
        additional_files = [
            'yaml_file',
            'dump_json_file',
            'log_file',
            'network_json_file'
        ]
        
        for file_key in additional_files:
            src_path = CHALLENGE_PATHS['kubernetes'][file_key]
            dest_path = os.path.join(temp_dir, os.path.basename(src_path))
            shutil.copy2(src_path, dest_path)

        # Create the final zip
        final_zip_path = os.path.join(temp_dir, f"{username}_kubernetes_challenge.zip")
        with zipfile.ZipFile(final_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add carany_image_build.zip
            zipf.write(carany_zip_path, arcname="carany_image_build.zip")
            # Add other individual files
            for file_key in additional_files:
                file_path = os.path.join(temp_dir, os.path.basename(CHALLENGE_PATHS['kubernetes'][file_key]))
                zipf.write(file_path, arcname=os.path.basename(file_path))

        def generate():
            with open(final_zip_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
            shutil.rmtree(temp_dir)

        return Response(
            generate(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{username}_kubernetes_challenge.zip"'}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/shadowInCiMassive', methods=['POST'])
def shadowInCiMassive_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get user info from auth endpoint - using POST request
        headers = { "Auth-token": token }
        res = requests.post(f"{CTF_BASE_URL}/api/auth/getuser", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get user info", "status_code": res.status_code}), res.status_code

        user_data = res.json()
        user_id = user_data["_id"]
        username = user_data["name"]

        # Load the userId.json file from configured path
        userid_path = CHALLENGE_PATHS['userIds']['userId_file']
        with open(userid_path, 'r') as f:
            teams = json.load(f)
        
        # Find the matching team by ID
        team = next((t for t in teams if t["id"] == user_id), None)
        if not team:
            return jsonify({"error": "User ID not found in teams"}), 404
        
        team_index = team["index"]
        
        # Determine which Jsploit file to use (cycle through 1-5)
        shadowInCiMassive_number = ((team_index - 1) % 5) + 1
        shadowInCiMassive_filename = f"shadowInCiMassive{shadowInCiMassive_number}.zip"
        shadowInCiMassive_path = CHALLENGE_PATHS['ShadowInCiMassive'][f"ShadowInCiMassive{shadowInCiMassive_number}"]
        
        if not os.path.exists(shadowInCiMassive_path):
            return jsonify({"error": f"splitFiction file {shadowInCiMassive_filename} not found"}), 404
        
        # Stream the response directly
        def generate():
            with open(shadowInCiMassive_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
        
        return Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="{username}"',
                'Content-Type': 'application/zip'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/BeaconInTheDark', methods=['POST'])
def shadowInCiMassive_challenge():
    try:
        data = request.json
        token = data.get("token")
        if not token:
            return jsonify({"error": "Missing token"}), 400

        # Get user info from auth endpoint - using POST request
        headers = { "Auth-token": token }
        res = requests.post(f"{CTF_BASE_URL}/api/auth/getuser", headers=headers)

        if res.status_code != 200:
            return jsonify({"error": "Failed to get user info", "status_code": res.status_code}), res.status_code

        user_data = res.json()
        user_id = user_data["_id"]
        username = user_data["name"]

        # Load the userId.json file from configured path
        userid_path = CHALLENGE_PATHS['userIds']['userId_file']
        with open(userid_path, 'r') as f:
            teams = json.load(f)
        
        # Find the matching team by ID
        team = next((t for t in teams if t["id"] == user_id), None)
        if not team:
            return jsonify({"error": "User ID not found in teams"}), 404
        
        team_index = team["index"]
        
        # Determine which Jsploit file to use (cycle through 1-5)
        BeaconInTheDark_number = ((team_index - 1) % 5) + 1
        BeaconInTheDark_filename = f"BeaconInTheDark{BeaconInTheDark_number}.zip"
        BeaconInTheDark_path = CHALLENGE_PATHS['BeaconInTheDark'][f"BeaconInTheDark{BeaconInTheDark_number}"]
        
        if not os.path.exists(BeaconInTheDark_path):
            return jsonify({"error": f"BeaconInTheDark file {BeaconInTheDark_filename} not found"}), 404
        
        # Stream the response directly
        def generate():
            with open(BeaconInTheDark_path, 'rb') as f:
                while chunk := f.read(1024):
                    yield chunk
        
        return Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename="BeaconInTheDark_{username}"',
                'Content-Type': 'application/zip'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True, port=5002)