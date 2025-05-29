from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
import requests
import os
import tempfile
import subprocess
import zipfile  # Using built-in zipfile instead of adm-zip
import shutil
import math

app = Flask(__name__)
CORS(app)
challenge_id = "682c3e5b088e4ef9fb77763f"
CTF_BASE_URL = "http://13.235.75.80:5050"

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

@app.route('/')
def index():
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

if __name__ == '__main__':
    app.run(debug=True, port=5002)