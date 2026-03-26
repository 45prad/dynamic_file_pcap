from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
import requests
import os
import io
import json
import tempfile
import subprocess
import zipfile
import shutil
import math
import random
import base64
import time
import pandas as pd
from datetime import datetime, timedelta
from scapy.all import IP, UDP, DNS, DNSQR, wrpcap, rdpcap, Raw, TCP, ICMP
import openpyxl
import numpy as np
import struct
from typing import List



app = Flask(__name__)
CORS(app)

# Base directory setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHALLENGES_DIR = os.path.join(BASE_DIR, 'challenges')

# Challenge IDs
CTF_BASE_URL = "http://35.154.8.207:8010"
UAV_CHALLENGE_ID = "69221aa7723650822dddef59"
SATCOMM3_CHALLENGE_ID = "6924664467c3bd541ff64b93"
SATCOMM4_CHALLENGE_ID = "6924898567c3bd541ff64c2e"

# Path configurations for each challenge
CHALLENGES_PATHS = {
    'UAV': {
        'logFile': os.path.join(CHALLENGES_DIR, 'UAV', 'uav_diag.log')
    },
    'satcomm3': {
        'helper1': os.path.join(CHALLENGES_DIR, 'satcomm3', 'helper_ccsds.py'),
        'helper2': os.path.join(CHALLENGES_DIR, 'satcomm3', 'helper_crc16.py'),
    }
}

# Import the required functions from the challenge modules
def crc16_ccitt(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    """
    Compute CRC-16-CCITT checksum.
    """
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) & 0xFFFF) ^ poly
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF

def bytes_to_bits(data: bytes) -> np.ndarray:
    """
    Convert bytes -> array of bits {0,1}.
    """
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    return bits.astype(np.int8)

def rrc_filter(beta: float, sps: int, span: int) -> np.ndarray:
    """
    Create Root Raised Cosine (RRC) filter taps.
    """
    N = span * sps
    t = np.arange(-N / 2, N / 2 + 1) / sps
    h = np.zeros_like(t, dtype=np.float64)

    for i, ti in enumerate(t):
        if ti == 0.0:
            h[i] = 1.0 - beta + (4 * beta / np.pi)
        elif abs(ti) == 1 / (4 * beta):
            h[i] = (beta / np.sqrt(2)) * (
                ((1 + 2 / np.pi) * np.sin(np.pi / (4 * beta))) +
                ((1 - 2 / np.pi) * np.cos(np.pi / (4 * beta)))
            )
        else:
            num = np.sin(np.pi * ti * (1 - beta)) + \
                  4 * beta * ti * np.cos(np.pi * ti * (1 + beta))
            den = np.pi * ti * (1 - (4 * beta * ti) ** 2)
            h[i] = num / den

    h /= np.sqrt(np.sum(h ** 2))
    return h

def bpsk_modulate(data: bytes,
                  sample_rate: float = 48000.0,
                  symbol_rate: float = 1200.0,
                  beta: float = 0.35,
                  span: int = 10,
                  carrier_offset_hz: float = 200.0) -> np.ndarray:
    """
    Turn bytes into BPSK complex IQ samples.
    """
    sps = int(sample_rate / symbol_rate)
    if sps * symbol_rate != sample_rate:
        raise ValueError("Sample rate must be integer multiple of symbol rate.")

    bits = bytes_to_bits(data)
    symbols = 2 * bits - 1
    symbols = symbols.astype(np.float64)

    up = np.zeros(len(symbols) * sps, dtype=np.float64)
    up[::sps] = symbols

    taps = rrc_filter(beta=beta, sps=sps, span=span)
    shaped = np.convolve(up, taps, mode='same')

    t = np.arange(len(shaped)) / sample_rate
    phase = 2 * np.pi * carrier_offset_hz * t
    carrier = np.exp(1j * phase)

    baseband = shaped.astype(np.complex128)
    sig = baseband * carrier

    sig /= np.max(np.abs(sig)) + 1e-9
    return sig.astype(np.complex64)

def build_primary_header(apid: int, seq_count: int, payload_len: int) -> bytes:
    """
    Build a 6-byte CCSDS-like primary header.
    """
    if not (0 <= apid <= 0x7FF):
        raise ValueError("APID must be 0..0x7FF")

    version = 0
    pkt_type = 0
    sec_hdr_flag = 0

    first_two = ((version & 0x7) << 13) | ((pkt_type & 0x1) << 12) | \
                ((sec_hdr_flag & 0x1) << 11) | (apid & 0x7FF)

    seq_flags = 0b11
    pkt_seq_count = seq_count & 0x3FFF
    second_two = ((seq_flags & 0x3) << 14) | pkt_seq_count

    pkt_len_field = (payload_len - 1) & 0xFFFF

    return struct.pack(">HHH", first_two, second_two, pkt_len_field)

def build_ccsds_frame(apid: int, seq_count: int, payload: bytes) -> bytes:
    """
    Build one CCSDS frame with sync word, header, payload, and CRC.
    """
    SYNC_WORD = 0x1ACFFC1D
    primary = build_primary_header(apid, seq_count, len(payload))

    crc_input = primary + payload
    crc = crc16_ccitt(crc_input)
    crc_le = struct.pack("<H", crc)

    return struct.pack(">I", SYNC_WORD) + primary + payload + crc_le

def make_demo_frames(flag: str) -> bytes:
    """
    Build a full sequence of frames with the flag embedded.
    """
    frames: List[bytes] = []
    seq = 0

    # Housekeeping packets
    hk_payloads = [
        b"HK: TEMP=18.5C VOLT=28.1V CURR=1.2A",
        b"HK: TEMP=18.6C VOLT=28.0V CURR=1.3A",
    ]
    for p in hk_payloads:
        frames.append(build_ccsds_frame(apid=0x042, seq_count=seq, payload=p))
        seq += 1

    # Attitude packets
    att_payloads = [
        b"ATT: Q=[0.01,0.99,0.01,0.00] ROLL=0.2 PITCH=-0.1 YAW=0.0",
        b"ATT: Q=[0.02,0.98,0.01,0.01] ROLL=0.3 PITCH=-0.1 YAW=0.1",
    ]
    for p in att_payloads:
        frames.append(build_ccsds_frame(apid=0x055, seq_count=seq, payload=p))
        seq += 1

    # The special packet containing the flag in APID 0x123
    flag_payload = f"PAYLOAD-DATA: flag{{{flag}}}".encode("ascii")
    frames.append(build_ccsds_frame(apid=0x123, seq_count=seq, payload=flag_payload))
    seq += 1

    # Final housekeeping packet
    frames.append(
        build_ccsds_frame(
            apid=0x042,
            seq_count=seq,
            payload=b"HK: FINAL SNAPSHOT BEFORE SILENCE",
        )
    )

    return b"".join(frames)



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
            f"{CTF_BASE_URL}/api/login",
            json=data
        )
        
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": "Login failed", "details": str(e)}), 500

@app.route('/uav', methods=['POST'])
def uav_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        # -----------------------------------------
        # 1. Fetch dynamic flag from CTF platform
        # -----------------------------------------
        headers = {"AuthToken": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/dynamicFlags/userFlag/{UAV_CHALLENGE_ID}",
            headers=headers,
            timeout=30
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch user flag", "status_code": response.status_code}), response.status_code

        flag_data = response.json()
        flag = flag_data.get('flag', '')
        
        if not flag:
            return jsonify({"error": "No flag received from API"}), 500

        print(f"Full flag received: {flag}")

        # -----------------------------------------
        # 2. Split into 4 parts dynamically
        # -----------------------------------------
        part_len = len(flag) // 4
        parts = [
            flag[0:part_len],
            flag[part_len:part_len*2],
            flag[part_len*2:part_len*3],
            flag[part_len*3:]
        ]

        print(f"Flag parts: {parts}")

        # -----------------------------------------
        # 3. XOR with 0x47 FIRST, then Base32 encode (NO padding)
        # -----------------------------------------
        EXFIL = []
        for p in parts:
            # XOR each character with 0x47 first
            xor_encoded = ''.join(chr(ord(c) ^ 0x47) for c in p)
            # Then Base32 encode
            base32_encoded = base64.b32encode(xor_encoded.encode()).decode().rstrip("=")
            EXFIL.append(base32_encoded)

        print(f"Flag parts XOR + Base32: {EXFIL}")

        # ================================
        # NORMAL DNS QUERIES (legit UAV telemetry)
        # ================================
        NORMAL_DNS = [
            "hb_0210.telemetry-sec.mil",
            "hb_0211.telemetry-sec.mil",
            "hb_0212.telemetry-sec.mil",
            "gpsfixA.telemetry-sec.mil",
            "gpsfixB.telemetry-sec.mil",
            "statuschk.telemetry-sec.mil",
            "heartbeat_uav.telemetry-sec.mil",
        ]

        # ================================
        # DECOY BASE32-LOOKING NOISE
        # ================================
        DECOY_DNS = [
            "IVZGSYLT.telemetry-sec.mil",
            "IVZGS===.telemetry-sec.mil",
            "IF2F6YLT.telemetry-sec.mil",
            "X5QL====.telem-secure.mil",
            "ONXXA4TF.telemetry.sec.srv",
            "ZQQQ====.opsrelay.net",
            "MJXW4ZJT.telemetry-sec.net",
        ]

        # ================================
        # TELEMETRY UDP PAYLOADS (NOISE)
        # ================================
        def make_telemetry():
            payload = bytes([random.randint(0, 255) for _ in range(random.randint(20, 60))])
            return (
                IP(src="192.168.100.23", dst="10.14.7.50", ttl=random.choice([32, 64, 128])) /
                UDP(sport=random.randint(20000, 60000), dport=5005) /
                Raw(payload)
            )

        # ================================
        # ICMP PING BURSTS
        # ================================
        def make_icmp():
            return (
                IP(src="192.168.100.23", dst="10.14.7.5") /
                ICMP(type="echo-request") /
                Raw(b"uav_ping_" + bytes([random.randint(0, 255)]))
            )

        # ================================
        # TCP SYN ATTEMPTS (FIREWALL-DROPPED)
        # ================================
        def make_tcp_attempt():
            return (
                IP(src="192.168.100.23", dst="10.14.7.10") /
                TCP(
                    sport=random.randint(20000, 60000),
                    dport=random.choice([80, 443, 8080]),
                    flags="S",
                    seq=random.randint(0, 99999999)
                )
            )

        # ================================
        # DNS QUERY BUILDER
        # ================================
        def make_dns(domain, qtype="A"):
            return (
                IP(src="192.168.100.23", dst="10.14.7.5") /
                UDP(sport=random.randint(1024, 65535), dport=53) /
                DNS(rd=1, id=random.randint(0, 65535),
                    qd=DNSQR(qname=domain, qtype=qtype))
            )

        # ================================
        # PACKET GENERATION (EXACTLY LIKE YOUR METHODOLOGY)
        # ================================
        packets = []

        # 1. TELEMETRY NOISE
        for _ in range(random.randint(40, 70)):
            packets.append(make_telemetry())
            time.sleep(0.002)

        # 2. ICMP PINGS
        for _ in range(random.randint(6, 12)):
            packets.append(make_icmp())
            time.sleep(0.002)

        # 3. NORMAL DNS TRAFFIC
        for _ in range(random.randint(50, 80)):
            packets.append(make_dns(random.choice(NORMAL_DNS), qtype="A"))
            time.sleep(0.002)

        # 4. DECOY TRAFFIC
        for decoy in DECOY_DNS:
            packets.append(make_dns(decoy, qtype="TXT"))
            time.sleep(0.003)

        # 5. REAL EXFIL FRAGMENTS (TXT QUERIES)
        for part in EXFIL:
            domain = f"{part}.telemetry-sec.mil"
            packets.append(make_dns(domain, qtype="TXT"))
            time.sleep(0.003)

        # 6. TCP ATTEMPTS
        for _ in range(random.randint(5, 10)):
            packets.append(make_tcp_attempt())
            time.sleep(0.002)

        # 7. SHUFFLE FOR REALISM
        random.shuffle(packets)

        # -----------------------------------------
        # 8. Create temporary directory and write files
        # -----------------------------------------
        temp_dir = tempfile.mkdtemp()
        pcap_path = os.path.join(temp_dir, "uav_capture.pcap")
        log_path = CHALLENGES_PATHS['UAV']['logFile']  # Get the log file path
        zip_path = os.path.join(temp_dir, "uav_challenge.zip")

        try:
            # Write PCAP file
            wrpcap(pcap_path, packets)
            
            # Create ZIP file with both PCAP and log file
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(pcap_path, arcname="uav_capture.pcap")
                zf.write(log_path, arcname="uav_diag.log")  # Add the log file

            # -----------------------------------------
            # 9. Stream ZIP to client
            # -----------------------------------------
            def generate():
                with open(zip_path, "rb") as f:
                    while chunk := f.read(4096):
                        yield chunk
                # Cleanup
                shutil.rmtree(temp_dir)

            return Response(
                generate(),
                mimetype='application/zip',
                headers={
                    "Content-Disposition": "attachment; filename=uav_challenge.zip",
                    "Content-Type": "application/zip"
                }
            )

        except Exception as e:
            shutil.rmtree(temp_dir)
            raise e

    except requests.RequestException as e:
        return jsonify({"error": "Failed to connect to flag service", "details": str(e)}), 502
    except Exception as e:
        return jsonify({"error": "Processing failed", "details": str(e)}), 500

@app.route('/signalInVoid', methods=['POST'])
def satcomm3_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        # -----------------------------------------
        # 1. Fetch dynamic flag from CTF platform
        # -----------------------------------------
        headers = {"AuthToken": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/dynamicFlags/userFlag/{SATCOMM3_CHALLENGE_ID}",
            headers=headers,
            timeout=30
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch user flag", "status_code": response.status_code}), response.status_code

        flag_data = response.json()
        full_flag = flag_data.get('flag', '')
        
        if not full_flag:
            return jsonify({"error": "No flag received from API"}), 500

        print(f"Full flag received: {full_flag}")

        # Extract flag content from FLAG{content} or flag{content}
        flag_content = ""
        if full_flag.startswith("FLAG{"):
            flag_content = full_flag[5:-1]  # Remove FLAG{ and }
        elif full_flag.startswith("flag{"):
            flag_content = full_flag[5:-1]  # Remove flag{ and }
        else:
            flag_content = full_flag  # Use as-is if no wrapper

        print(f"Flag content: {flag_content}")

        # -----------------------------------------
        # 2. Generate the challenge files
        # -----------------------------------------
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Generate CCSDS frames with the flag
            frames = make_demo_frames(flag_content)
            print(f"[+] Built {len(frames)} bytes of CCSDS frames.")

            # Modulate frames to BPSK IQ samples
            sample_rate = 48000.0
            symbol_rate = 1200.0
            rolloff = 0.35
            carrier_offset_hz = 200.0

            iq = bpsk_modulate(
                frames,
                sample_rate=sample_rate,
                symbol_rate=symbol_rate,
                beta=rolloff,
                span=10,
                carrier_offset_hz=carrier_offset_hz,
            )
            print(f"[+] Generated {len(iq)} complex samples.")

            # Save IQ file
            iq_filename = "dl_helios_2089_06_03.iq"
            iq_path = os.path.join(temp_dir, iq_filename)
            iq.astype(np.complex64).tofile(iq_path)
            print(f"[+] Wrote IQ data to {iq_path}")

            # Save metadata file
            meta_filename = "metadata_dl_helios_2089_06_03.txt"
            meta_path = os.path.join(temp_dir, meta_filename)
            with open(meta_path, "w") as f:
                f.write(
                    "Helios-IV Downlink Capture Metadata\n"
                    "-----------------------------------\n"
                    "File: dl_helios_2089_06_03.iq\n"
                    "\n"
                    "Modulation: BPSK (NRZ)\n"
                    "Sample rate: 48000 Hz\n"
                    "Symbol rate: 1200 baud\n"
                    "Samples per symbol: 40\n"
                    "RRC roll-off: 0.35\n"
                    "Carrier frequency offset: ~+200 Hz (within ±500 Hz window)\n"
                    "\n"
                    "Frame sync word: 0x1ACFFC1D (32-bit, MSByte first in stream)\n"
                    "Packet CRC: CRC-16-CCITT, poly x^16 + x^12 + x^5 + 1, LSByte first\n"
                    "\n"
                    "Payload subsystem APID: 0x0123\n"
                    "\n"
                    "IQ format: complex64, interleaved float32 I and Q samples.\n"
                )
            print(f"[+] Wrote metadata to {meta_path}")

            # Copy helper files
            helper1_path = CHALLENGES_PATHS['satcomm3']['helper1']
            helper2_path = CHALLENGES_PATHS['satcomm3']['helper2']
            
            helper1_dest = os.path.join(temp_dir, "helper_ccsds.py")
            helper2_dest = os.path.join(temp_dir, "helper_crc16.py")
            
            shutil.copy2(helper1_path, helper1_dest)
            shutil.copy2(helper2_path, helper2_dest)
            print("[+] Copied helper files")

            # Create ZIP file
            zip_path = os.path.join(temp_dir, "satcomm3_challenge.zip")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(iq_path, arcname=iq_filename)
                zf.write(meta_path, arcname=meta_filename)
                zf.write(helper1_dest, arcname="helper_ccsds.py")
                zf.write(helper2_dest, arcname="helper_crc16.py")

            # -----------------------------------------
            # 3. Stream ZIP to client
            # -----------------------------------------
            def generate():
                with open(zip_path, "rb") as f:
                    while chunk := f.read(4096):
                        yield chunk
                # Cleanup
                shutil.rmtree(temp_dir)

            return Response(
                generate(),
                mimetype='application/zip',
                headers={
                    "Content-Disposition": "attachment; filename=satcomm3_challenge.zip",
                    "Content-Type": "application/zip"
                }
            )

        except Exception as e:
            shutil.rmtree(temp_dir)
            raise e

    except requests.RequestException as e:
        return jsonify({"error": "Failed to connect to flag service", "details": str(e)}), 502
    except Exception as e:
        return jsonify({"error": "Processing failed", "details": str(e)}), 500


@app.route('/satcomm4', methods=['POST'])
def satcomm4_challenge():
    data = request.json
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        # -----------------------------------------
        # 1. Fetch dynamic flag from CTF platform
        # -----------------------------------------
        headers = {"AuthToken": token}
        response = requests.get(
            f"{CTF_BASE_URL}/api/dynamicFlags/userFlag/{SATCOMM4_CHALLENGE_ID}",  # You'll need to define this
            headers=headers,
            timeout=30
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch user flag", "status_code": response.status_code}), response.status_code

        flag_data = response.json()
        full_flag = flag_data.get('flag', '')
        
        if not full_flag:
            return jsonify({"error": "No flag received from API"}), 500

        print(f"Full flag received: {full_flag}")

        # Extract flag content from FLAG{content} or flag{content}
        flag_content = ""
        if full_flag.startswith("FLAG{"):
            flag_content = full_flag[5:-1]  # Remove FLAG{ and }
        elif full_flag.startswith("flag{"):
            flag_content = full_flag[5:-1]  # Remove flag{ and }
        else:
            flag_content = full_flag  # Use as-is if no wrapper

        print(f"Flag content: {flag_content}")

        # -----------------------------------------
        # 2. Create temporary directory for file generation
        # -----------------------------------------
        temp_dir = tempfile.mkdtemp()
        
        try:
            # -----------------------------------------
            # 3. Generate bus_logs.bin with the flag embedded
            # -----------------------------------------
            def generate_bus_logs(flag: str, output_dir: str) -> str:
                bus_logs_path = os.path.join(output_dir, "bus_logs.bin")
                
                MAGIC = b"BLOG"
                VERSION = 1
                FRAME_STRUCT = struct.Struct("<I I B B 8s")  # ts_ms, can_id, dlc, flags, data[8]
                STARTRACK_CAN_ID = 0x0000042F
                FLAG_STARTRACK = 0x01  # bit0 == 1

                def build_header_text() -> bytes:
                    return (
                        b"HELIOS-IV BUS LOG SNAPSHOT\n"
                        b"Format: ts_ms,u32_can_id,dlc,flags,data[8]\n"
                        b"flags bit0=1 => startracker\n"
                    )

                def chunk8(b: bytes):
                    for i in range(0, len(b), 8):
                        yield b[i:i+8]

                header_text = build_header_text()
                header_len = len(header_text)

                # Binary header: magic + version + header_len
                header = struct.pack("<4sII", MAGIC, VERSION, header_len) + header_text

                frames = []

                # --- Some non-startracker "noise" frames ---
                frames.append(FRAME_STRUCT.pack(100, 0x00000123, 8, 0x00, b"\x01\x02\x03\x04TEST"))
                frames.append(FRAME_STRUCT.pack(200, 0x00000055, 4, 0x00, b"ABCD\x00\x00\x00\x00"))
                frames.append(FRAME_STRUCT.pack(300, 0x00000099, 8, 0x00, b"\x10\x20\x30\x40\x50\x60\x70\x80"))

                # --- Startracker frames with flag embedded ---
                # We interleave 0x00 between characters, so `strings` doesn't show a clean word.
                constellation_plain = f"CONSTELLATION:FLAG{{{flag}}}\n".encode()
                encoded = bytearray()
                for c in constellation_plain:
                    encoded.append(c)
                    encoded.append(0x00)  # break up ASCII sequence

                # pad to multiple of 8 bytes for CAN payloads
                while len(encoded) % 8 != 0:
                    encoded.append(0x00)

                ts = 1000
                for payload in chunk8(bytes(encoded)):
                    frames.append(
                        FRAME_STRUCT.pack(
                            ts,
                            STARTRACK_CAN_ID,
                            8,                 # dlc
                            FLAG_STARTRACK,    # flags bit0=1 => startracker
                            payload,
                        )
                    )
                    ts += 100

                body = b"".join(frames)
                with open(bus_logs_path, 'wb') as f:
                    f.write(header + body)
                
                print(f"Generated bus_logs.bin: {len(header)}-byte header, {len(frames)} frames")
                return bus_logs_path

            # -----------------------------------------
            # 4. Generate ram_dump.bin using the bus_logs.bin
            # -----------------------------------------
            def generate_ram_dump(bus_logs_path: str, output_dir: str) -> str:
                ram_dump_path = os.path.join(output_dir, "ram_dump.bin")
                
                MAGIC = b"HLIV"
                VERSION = 1
                STARTRACKER_CAN_ID = 0x0000042F
                LOG_OFFSET = 0x00000200  # where we embed the bus logs in this fake RAM
                CRC_RAM = 0xABCD
                CRC_LOGS = 0x1234

                with open(bus_logs_path, 'rb') as f:
                    bus_bytes = f.read()
                
                log_length = len(bus_bytes)

                # 1) Build binary header
                header = struct.pack(
                    "<4sIIIIHH",
                    MAGIC,
                    VERSION,
                    STARTRACKER_CAN_ID,
                    LOG_OFFSET,
                    log_length,
                    CRC_RAM,
                    CRC_LOGS,
                )

                # 2) Build a small "registers" section with bit-flips
                true_reg1 = 0xDEADBEEF
                true_reg2 = 0xCAFEBABE
                true_status = 0b00000101  # bit0: startracker enabled, bit2: CRC OK

                # Corrupt one bit in reg2 and one bit in status to simulate CME
                corrupt_reg2 = true_reg2 ^ (1 << 7)   # flip bit 7
                corrupt_status = true_status ^ (1 << 2)

                regs = struct.pack("<IIB", true_reg1, corrupt_reg2, corrupt_status)

                # 3) Human-readable guidance strings (to be seen with `strings`)
                text = (
                    b"HELIOS-IV FDIR DEBUG SNAPSHOT\n"
                    b"Snapshot captured after suspected CME bit-flip event.\n"
                    b"Fields below are what the flight software THINKS is true.\n"
                    b"Use them to repair the on-board view of the bus.\n"
                    b"STARTRACK_CAN_ID=0x%08X\n" % STARTRACKER_CAN_ID +
                    b"LOG_OFFSET=0x%08X\n" % LOG_OFFSET +
                    b"LOG_LENGTH=%d bytes\n" % log_length +
                    b"CRC_RAM_EXPECTED=0x%04X\n" % CRC_RAM +
                    b"CRC_LOGS_EXPECTED=0x%04X\n" % CRC_LOGS
                )

                # 4) Pad from end of (header + regs + text) up to LOG_OFFSET
                pre_logs = header + regs + text
                if len(pre_logs) > LOG_OFFSET:
                    raise RuntimeError("Pre-log region longer than LOG_OFFSET, increase LOG_OFFSET.")

                padding = b"\x00" * (LOG_OFFSET - len(pre_logs))

                # 5) Final RAM image: [header|regs|text|padding|bus_logs]
                ram_image = pre_logs + padding + bus_bytes

                with open(ram_dump_path, 'wb') as f:
                    f.write(ram_image)
                
                print(f"Generated ram_dump.bin ({len(ram_image)} bytes) with embedded logs at 0x{LOG_OFFSET:08X}")
                return ram_dump_path

            # Generate the files
            bus_logs_path = generate_bus_logs(flag_content, temp_dir)
            ram_dump_path = generate_ram_dump(bus_logs_path, temp_dir)

            # -----------------------------------------
            # 5. Create ZIP file with both binaries
            # -----------------------------------------
            zip_path = os.path.join(temp_dir, "satcomm4_challenge.zip")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(bus_logs_path, arcname="bus_logs.bin")
                zf.write(ram_dump_path, arcname="ram_dump.bin")

            # -----------------------------------------
            # 6. Stream ZIP to client
            # -----------------------------------------
            def generate():
                with open(zip_path, "rb") as f:
                    while chunk := f.read(4096):
                        yield chunk
                # Cleanup
                shutil.rmtree(temp_dir)

            return Response(
                generate(),
                mimetype='application/zip',
                headers={
                    "Content-Disposition": "attachment; filename=satcomm4_challenge.zip",
                    "Content-Type": "application/zip"
                }
            )

        except Exception as e:
            shutil.rmtree(temp_dir)
            raise e

    except requests.RequestException as e:
        return jsonify({"error": "Failed to connect to flag service", "details": str(e)}), 502
    except Exception as e:
        return jsonify({"error": "Processing failed", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5002)