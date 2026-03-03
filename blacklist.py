import base64
import json
import socket
import time
import traceback
import warnings
from datetime import datetime
from typing import List, Dict, Any

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, render_template_string, request, jsonify
from google.protobuf.timestamp_pb2 import Timestamp

warnings.filterwarnings('ignore')

# ----------------- SimpleProtobuf Class (unchanged) -----------------
class SimpleProtobuf:
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    @staticmethod
    def decode_varint(data, start_index=0):
        value = 0
        shift = 0
        index = start_index
        while index < len(data):
            byte = data[index]
            index += 1
            value |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return value, index

    @staticmethod
    def parse_protobuf(data):
        result = {}
        index = 0
        while index < len(data):
            if index >= len(data):
                break
            tag = data[index]
            field_num = tag >> 3
            wire_type = tag & 0x07
            index += 1
            if wire_type == 0:  # Varint
                value, index = SimpleProtobuf.decode_varint(data, index)
                result[field_num] = value
            elif wire_type == 2:  # Length-delimited
                length, index = SimpleProtobuf.decode_varint(data, index)
                if index + length <= len(data):
                    value_bytes = data[index:index + length]
                    index += length
                    try:
                        result[field_num] = value_bytes.decode('utf-8')
                    except:
                        result[field_num] = value_bytes
            else:
                break
        return result

    @staticmethod
    def encode_string(field_number, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 2))
        result.extend(SimpleProtobuf.encode_varint(len(value)))
        result.extend(value)
        return bytes(result)

    @staticmethod
    def encode_int32(field_number, value):
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 0))
        result.extend(SimpleProtobuf.encode_varint(value))
        return bytes(result)

    @staticmethod
    def create_login_payload(open_id, access_token, platform):
        payload = bytearray()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload.extend(SimpleProtobuf.encode_string(3, current_time))
        payload.extend(SimpleProtobuf.encode_string(4, 'free fire'))
        payload.extend(SimpleProtobuf.encode_int32(5, 1))
        payload.extend(SimpleProtobuf.encode_string(7, '2.111.2'))
        payload.extend(SimpleProtobuf.encode_string(8, 'Android OS 12 / API-31 (SP1A.210812.016/T505NDXS6CXB1)'))
        payload.extend(SimpleProtobuf.encode_string(9, 'Handheld'))
        payload.extend(SimpleProtobuf.encode_string(10, 'we'))
        payload.extend(SimpleProtobuf.encode_string(11, 'WIFI'))
        payload.extend(SimpleProtobuf.encode_int32(12, 1334))
        payload.extend(SimpleProtobuf.encode_int32(13, 800))
        payload.extend(SimpleProtobuf.encode_string(14, '225'))
        payload.extend(SimpleProtobuf.encode_string(15, 'ARM64 FP ASIMD AES | 4032 | 8'))
        payload.extend(SimpleProtobuf.encode_int32(16, 2705))
        payload.extend(SimpleProtobuf.encode_string(17, 'Adreno (TM) 610'))
        payload.extend(SimpleProtobuf.encode_string(18, 'OpenGL ES 3.2 V@0502.0 (GIT@5eaa426211, I07ee46fc66, 1633700387) (Date:10/08/21)'))
        payload.extend(SimpleProtobuf.encode_string(19, 'Google|dbc5b426-9715-454a-9466-6c82e151d407'))
        payload.extend(SimpleProtobuf.encode_string(20, '154.183.6.12'))
        payload.extend(SimpleProtobuf.encode_string(21, 'ar'))
        payload.extend(SimpleProtobuf.encode_string(22, open_id))
        payload.extend(SimpleProtobuf.encode_string(23, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(24, 'Handheld'))
        payload.extend(SimpleProtobuf.encode_string(25, 'samsung SM-T505N'))
        payload.extend(SimpleProtobuf.encode_string(29, access_token))
        payload.extend(SimpleProtobuf.encode_int32(30, 1))
        payload.extend(SimpleProtobuf.encode_string(41, 'we'))
        payload.extend(SimpleProtobuf.encode_string(42, 'WIFI'))
        payload.extend(SimpleProtobuf.encode_string(57, 'e89b158e4bcf988ebd09eb83f5378e87'))
        payload.extend(SimpleProtobuf.encode_int32(60, 22394))
        payload.extend(SimpleProtobuf.encode_int32(61, 1424))
        payload.extend(SimpleProtobuf.encode_int32(62, 3349))
        payload.extend(SimpleProtobuf.encode_int32(63, 24))
        payload.extend(SimpleProtobuf.encode_int32(64, 1552))
        payload.extend(SimpleProtobuf.encode_int32(65, 22394))
        payload.extend(SimpleProtobuf.encode_int32(66, 1552))
        payload.extend(SimpleProtobuf.encode_int32(67, 22394))
        payload.extend(SimpleProtobuf.encode_int32(73, 1))
        payload.extend(SimpleProtobuf.encode_string(74, '/data/app/~~lqYdjEs9bd43CagTaQ9JPg==/com.dts.freefiremax-i72Sh_-sI0zZHs5Bw6aufg==/lib/arm64'))
        payload.extend(SimpleProtobuf.encode_string(77, 'b4d2689433917e66100ba91db790bf37|/data/app/~~lqYdjEs9bd43CagTaQ9JPg==/com.dts.freefiremax-i72Sh_-sI0zZHs5Bw6aufg==/base.apk'))
        payload.extend(SimpleProtobuf.encode_int32(78, 2))
        payload.extend(SimpleProtobuf.encode_int32(79, 2))
        payload.extend(SimpleProtobuf.encode_string(81, '64'))
        payload.extend(SimpleProtobuf.encode_string(83, '2019115296'))
        payload.extend(SimpleProtobuf.encode_int32(85, 1))
        payload.extend(SimpleProtobuf.encode_string(86, 'OpenGLES3'))
        payload.extend(SimpleProtobuf.encode_int32(87, 16383))
        payload.extend(SimpleProtobuf.encode_int32(88, 4))
        payload.extend(SimpleProtobuf.encode_string(90, 'Damanhur'))
        payload.extend(SimpleProtobuf.encode_string(91, 'BH'))
        payload.extend(SimpleProtobuf.encode_int32(92, 31095))
        payload.extend(SimpleProtobuf.encode_string(93, 'android_max'))
        payload.extend(SimpleProtobuf.encode_string(94, 'KqsHTzpfADfqKnEg/KMctJLElsm8bN2M4ts0zq+ifY+560USyjMSDL386RFrwRloT0ZSbMxEuM+Y4FSvjghQQZXWWpY='))
        payload.extend(SimpleProtobuf.encode_int32(97, 1))
        payload.extend(SimpleProtobuf.encode_int32(98, 1))
        payload.extend(SimpleProtobuf.encode_string(99, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(100, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(102, ''))
        return bytes(payload)

# ----------------- Helper Functions -----------------
def b64url_decode(input_str: str) -> bytes:
    rem = len(input_str) % 4
    if rem:
        input_str += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input_str)

def get_available_room(input_text):
    try:
        data = bytes.fromhex(input_text)
        result = {}
        index = 0
        while index < len(data):
            if index >= len(data):
                break
            tag = data[index]
            field_num = tag >> 3
            wire_type = tag & 0x07
            index += 1
            if wire_type == 0:  # Varint
                value = 0
                shift = 0
                while index < len(data):
                    byte = data[index]
                    index += 1
                    value |= (byte & 0x7F) << shift
                    if not (byte & 0x80):
                        break
                    shift += 7
                result[str(field_num)] = {"wire_type": "varint", "data": value}
            elif wire_type == 2:  # Length-delimited
                length = 0
                shift = 0
                while index < len(data):
                    byte = data[index]
                    index += 1
                    length |= (byte & 0x7F) << shift
                    if not (byte & 0x80):
                        break
                    shift += 7
                if index + length <= len(data):
                    value_bytes = data[index:index + length]
                    index += length
                    try:
                        value_str = value_bytes.decode('utf-8')
                        result[str(field_num)] = {"wire_type": "string", "data": value_str}
                    except:
                        result[str(field_num)] = {"wire_type": "bytes", "data": value_bytes.hex()}
            else:
                break
        return json.dumps(result)
    except Exception as e:
        return None

def extract_jwt_payload_dict(jwt_s: str):
    try:
        parts = jwt_s.split('.')
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        payload_bytes = b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8', errors='ignore'))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return None

def encrypt_packet(hex_string: str, aes_key, aes_iv) -> str:
    if isinstance(aes_key, str):
        aes_key = bytes.fromhex(aes_key)
    if isinstance(aes_iv, str):
        aes_iv = bytes.fromhex(aes_iv)
    data = bytes.fromhex(hex_string)
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return encrypted.hex()

def build_start_packet(account_id: int, timestamp: int, jwt: str, key, iv) -> str:
    try:
        encrypted = encrypt_packet(jwt.encode().hex(), key, iv)
        head_len = hex(len(encrypted) // 2)[2:]
        ide_hex = hex(int(account_id))[2:]
        zeros = "0" * (16 - len(ide_hex))
        timestamp_hex = hex(timestamp)[2:].zfill(2)
        head = f"0115{zeros}{ide_hex}{timestamp_hex}00000{head_len}"
        start_packet = head + encrypted
        return start_packet
    except Exception as e:
        return None

def send_once(remote_ip, remote_port, payload_bytes, recv_timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(recv_timeout)
    try:
        s.connect((remote_ip, remote_port))
        s.sendall(payload_bytes)
        chunks = []
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        return b"".join(chunks)
    finally:
        s.close()

# ----------------- Flask App -----------------
app = Flask(__name__)

# Embedded HTML template (same premium design, but modified JS for synchronous call)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FreeFire Login · AI Console</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        /* ----- Your Complete Premium CSS ----- */
        :root {
            --primary: #6c5ce7;
            --primary-glow: rgba(108, 92, 231, 0.4);
            --secondary: #00cec9;
            --dark-bg: #0f0f13;
            --card-bg: rgba(25, 25, 35, 0.7);
            --text: #dfe6e9;
            --text-muted: #b2bec3;
            --success: #00b894;
            --danger: #d63031;
            --border: 1px solid rgba(255, 255, 255, 0.1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Outfit', sans-serif;
        }

        body {
            background-color: var(--dark-bg);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            padding: 20px;
        }

        .background-globes {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            overflow: hidden;
        }

        .globe {
            position: absolute;
            border-radius: 50%;
            filter: blur(80px);
            opacity: 0.6;
            animation: float 10s infinite ease-in-out;
        }

        .globe-1 {
            width: 300px;
            height: 300px;
            background: var(--primary);
            top: -50px;
            left: -50px;
        }

        .globe-2 {
            width: 400px;
            height: 400px;
            background: var(--secondary);
            bottom: -100px;
            right: -100px;
            animation-delay: 2s;
        }

        .globe-3 {
            width: 200px;
            height: 200px;
            background: #e056fd;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            opacity: 0.3;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0) scale(1); }
            50% { transform: translateY(20px) scale(1.1); }
        }

        .app-container {
            width: 100%;
            max-width: 600px;
            position: relative;
            z-index: 10;
        }

        header {
            text-align: center;
            margin-bottom: 40px;
            animation: fadeInDown 0.8s ease;
        }

        header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .highlight {
            color: var(--secondary);
            text-shadow: 0 0 15px var(--secondary);
        }

        header p {
            color: var(--text-muted);
            font-size: 1rem;
            letter-spacing: 1px;
        }

        .menu-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            animation: fadeInUp 0.8s ease backwards;
        }

        .menu-card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            border: var(--border);
            border-radius: 20px;
            padding: 25px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            position: relative;
            overflow: hidden;
        }

        .menu-card:hover {
            transform: translateY(-5px);
            border-color: var(--primary);
            box-shadow: 0 10px 30px -10px var(--primary-glow);
        }

        .menu-card .icon-box {
            font-size: 2rem;
            margin-bottom: 15px;
            color: var(--text);
            background: rgba(255, 255, 255, 0.05);
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-left: auto;
            margin-right: auto;
            transition: 0.3s;
        }

        .menu-card:hover .icon-box {
            background: var(--primary);
            color: white;
            transform: rotate(10deg);
        }

        .menu-card h3 {
            margin-bottom: 8px;
            font-size: 1.4rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            background: linear-gradient(90deg, #fff, #74b9ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            filter: drop-shadow(0 0 5px rgba(116, 185, 255, 0.3));
        }

        .menu-card p {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-weight: 400;
        }

        .highlight-card h3 {
            background: linear-gradient(90deg, #fff, #ffeaa7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            filter: drop-shadow(0 0 5px rgba(255, 234, 167, 0.3));
        }

        .highlight-card {
            grid-column: span 2;
            background: linear-gradient(135deg, rgba(108, 92, 231, 0.2), rgba(0, 206, 201, 0.1));
            border-color: rgba(108, 92, 231, 0.5);
        }

        footer {
            text-align: center;
            margin-top: 50px;
            padding-bottom: 20px;
            color: var(--text-muted);
            font-size: 0.8rem;
            opacity: 0.7;
        }

        .config-card {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 25px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 10px;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        input[type="text"] {
            width: 100%;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 12px;
            color: white;
            font-size: 1rem;
            outline: none;
            transition: 0.3s;
        }

        input:focus {
            border-color: var(--secondary);
            box-shadow: 0 0 10px rgba(0, 206, 201, 0.2);
        }

        .action-btn {
            width: 100%;
            background: linear-gradient(90deg, var(--primary), #8e7bf8);
            border: none;
            padding: 16px;
            border-radius: 15px;
            color: white;
            font-size: 1.1rem;
            font-weight: 700;
            cursor: pointer;
            transition: 0.3s;
            box-shadow: 0 5px 15px var(--primary-glow);
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
        }

        .action-btn:active {
            transform: scale(0.98);
        }

        .action-btn:disabled,
        .action-btn.disabled {
            filter: grayscale(100%);
            cursor: not-allowed;
            opacity: 0.6;
            transform: none;
        }

        /* Additional styles for console */
        .log-container {
            background: rgba(0, 0, 0, 0.5);
            border: var(--border);
            border-radius: 16px;
            padding: 20px;
            margin-top: 30px;
            backdrop-filter: blur(10px);
        }
        .log-output {
            background: rgba(0, 0, 0, 0.7);
            border-radius: 12px;
            padding: 15px;
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.5;
            color: #0f0;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .log-output .log-info { color: #00cec9; }
        .log-output .log-success { color: #00b894; }
        .log-output .log-error { color: #d63031; }
        .log-output .log-wait { color: #fdcb6e; }
        .result-packet {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 15px;
            margin-top: 20px;
            word-break: break-all;
            font-family: monospace;
        }
        .status-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-left: 10px;
            background: rgba(255,255,255,0.1);
        }
        .status-badge.running { background: var(--primary); color: white; }
        .status-badge.done { background: var(--success); color: white; }
        .status-badge.error { background: var(--danger); color: white; }
        .spinner {
            border: 3px solid rgba(255,255,255,0.1);
            border-top: 3px solid var(--secondary);
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Animations */
        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.1);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 10px;
        }

        @media (max-width: 480px) {
            body { padding: 15px; }
            header h1 { font-size: 2rem; }
            .menu-grid { grid-template-columns: 1fr; }
            .highlight-card { grid-column: span 1; }
            .action-btn { font-size: 1rem; padding: 14px; }
        }
    </style>
</head>
<body>
    <div class="background-globes">
        <div class="globe globe-1"></div>
        <div class="globe globe-2"></div>
        <div class="globe globe-3"></div>
    </div>
    <div class="app-container">
        <header>
            <h1>free<span class="highlight">fire</span>.</h1>
            <p>PREMIUM LOGIN CONSOLE · AI STYLED</p>
        </header>

        <div class="menu-grid" id="mainMenu">
            <div class="menu-card highlight-card" id="startCard">
                <div class="icon-box">🚀</div>
                <h3>START LOGIN</h3>
                <p>Enter access token below</p>
            </div>
        </div>

        <div class="config-card" style="margin-top: 20px;">
            <div class="form-group">
                <label><i class="fas fa-key"></i> ACCESS TOKEN</label>
                <input type="text" id="tokenInput" placeholder="Paste your Garena access token here...">
            </div>
            <button class="action-btn" id="runBtn" style="margin-top: 10px;">
                <i class="fas fa-play"></i> EXECUTE LOGIN
            </button>
        </div>

        <div class="log-container" id="logContainer" style="display: none;">
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <h3 style="margin:0;">LIVE CONSOLE</h3>
                <span class="status-badge" id="statusBadge">idle</span>
            </div>
            <div class="log-output" id="logOutput">
                <!-- Logs will appear here -->
            </div>
            <div class="result-packet" id="resultPacket" style="display: none;">
                <strong>FINAL PACKET</strong><br>
                <span id="packetHex"></span>
            </div>
        </div>

        <footer>
            <p>⚡ AI‑enhanced console · all operations run in memory</p>
        </footer>
    </div>

    <!-- Font Awesome for icons -->
    <script src="https://kit.fontawesome.com/a076d05399.js" crossorigin="anonymous"></script>
    <script>
        const logOutput = document.getElementById('logOutput');
        const logContainer = document.getElementById('logContainer');
        const statusBadge = document.getElementById('statusBadge');
        const resultPacketDiv = document.getElementById('resultPacket');
        const packetHexSpan = document.getElementById('packetHex');
        const runBtn = document.getElementById('runBtn');
        const tokenInput = document.getElementById('tokenInput');

        function addLog(level, message) {
            const line = document.createElement('div');
            line.className = `log-${level}`;
            line.textContent = message;
            logOutput.appendChild(line);
            logOutput.scrollTop = logOutput.scrollHeight;
        }

        function clearLogs() {
            logOutput.innerHTML = '';
            resultPacketDiv.style.display = 'none';
        }

        function showLoading() {
            statusBadge.textContent = 'running';
            statusBadge.className = 'status-badge running';
            runBtn.disabled = true;
            runBtn.classList.add('disabled');
            // Change button text to spinner
            runBtn.innerHTML = '<span class="spinner"></span> PROCESSING...';
        }

        function hideLoading() {
            runBtn.disabled = false;
            runBtn.classList.remove('disabled');
            runBtn.innerHTML = '<i class="fas fa-play"></i> EXECUTE LOGIN';
        }

        async function startSession(token) {
            clearLogs();
            logContainer.style.display = 'block';
            showLoading();

            try {
                const response = await fetch('/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: token })
                });

                const data = await response.json();

                if (data.error) {
                    addLog('error', 'Error: ' + data.error);
                    statusBadge.textContent = 'error';
                    statusBadge.className = 'status-badge error';
                } else {
                    // Display all logs
                    data.logs.forEach(log => {
                        addLog(log.level, log.message);
                    });

                    if (data.success) {
                        statusBadge.textContent = 'done';
                        statusBadge.className = 'status-badge done';
                        if (data.packet) {
                            packetHexSpan.textContent = data.packet;
                            resultPacketDiv.style.display = 'block';
                        }
                    } else {
                        statusBadge.textContent = 'error';
                        statusBadge.className = 'status-badge error';
                    }
                }
            } catch (err) {
                addLog('error', 'Network error: ' + err.message);
                statusBadge.textContent = 'error';
                statusBadge.className = 'status-badge error';
            } finally {
                hideLoading();
            }
        }

        runBtn.addEventListener('click', function() {
            const token = tokenInput.value.trim();
            if (!token) {
                alert('Please enter an access token');
                return;
            }
            startSession(token);
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/run', methods=['POST'])
def run_login():
    token = request.json.get('token')
    if not token:
        return jsonify({'error': 'Token required'}), 400

    logs: List[Dict[str, str]] = []
    def log(msg, level="info"):
        logs.append({"level": level, "message": msg})

    try:
        log("=" * 60, "info")
        log("         FreeFire Login Script", "info")
        log("=" * 60, "info")
        log("", "info")

        log("[*] Starting login process...", "wait")
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={token}"
        inspect_headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"
        }

        try:
            resp = requests.get(inspect_url, headers=inspect_headers, timeout=10)
            data = resp.json()
            log("[INFO] Inspect response: " + json.dumps(data, indent=2), "info")
            if 'error' in data:
                log("[!] Token error: " + data.get('error'), "error")
                return jsonify({"success": False, "logs": logs})
        except Exception as e:
            log("[!] Failed to inspect access token: " + str(e), "error")
            return jsonify({"success": False, "logs": logs})

        NEW_OPEN_ID = data.get('open_id')
        platform_ = data.get('platform')
        log(f"[✓] Open ID: {NEW_OPEN_ID}", "success")
        log(f"[✓] Platform: {platform_}", "success")

        log("", "info")
        log("[2] Performing MajorLogin...", "wait")
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        MajorLogin_url = "https://loginbp.ggblueshark.com/MajorLogin"
        MajorLogin_headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E Build/TP1A.220624.014)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1",
            "ReleaseVersion": "OB52"
        }

        data_pb = SimpleProtobuf.create_login_payload(NEW_OPEN_ID, token, str(platform_))
        data_padded = pad(data_pb, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc_data = cipher.encrypt(data_padded)

        try:
            response = requests.post(MajorLogin_url, headers=MajorLogin_headers, data=enc_data, timeout=15)
            log(f"[INFO] MajorLogin HTTP status: {response.status_code}", "info")
        except Exception as e:
            log("[!] MajorLogin request failed: " + str(e), "error")
            return jsonify({"success": False, "logs": logs})

        if not response.ok:
            log("[!] MajorLogin returned error code: " + str(response.status_code), "error")
            return jsonify({"success": False, "logs": logs})

        resp_enc = response.content
        cipher_resp = AES.new(key, AES.MODE_CBC, iv)
        try:
            resp_dec = unpad(cipher_resp.decrypt(resp_enc), 16)
            parsed = SimpleProtobuf.parse_protobuf(resp_dec)
            log("[✓] Parsed MajorLoginRes from decrypted payload", "success")
        except:
            parsed = SimpleProtobuf.parse_protobuf(resp_enc)
            log("[✓] Parsed MajorLoginRes from raw payload", "success")

        account_id = parsed.get(2, 0)
        jwt = parsed.get(3, "")
        key_hex = parsed.get(4, b'').hex() if isinstance(parsed.get(4), bytes) else ""
        iv_hex = parsed.get(5, b'').hex() if isinstance(parsed.get(5), bytes) else ""

        log(f"[✓] Account ID: {account_id}", "success")
        log(f"[✓] JWT: {jwt[:50]}...", "success")
        log(f"[✓] Key: {key_hex}", "success")
        log(f"[✓] IV: {iv_hex}", "success")

        field_21_value = parsed.get(21, None)
        if field_21_value:
            log(f"[✓] Field 21 extracted: {field_21_value}", "success")
            ts = Timestamp()
            ts.FromNanoseconds(field_21_value)
            timetamp = ts.seconds * 1_000_000_000 + ts.nanos
        else:
            payload = extract_jwt_payload_dict(jwt)
            exp = int(payload.get("exp", 0))
            ts = Timestamp()
            ts.FromNanoseconds(exp * 1_000_000_000)
            timetamp = ts.seconds * 1_000_000_000 + ts.nanos
        log(f"[✓] Calculated timetamp: {timetamp}", "success")

        log("", "info")
        log("[3] Getting login data...", "wait")
        GetLoginData_resURL = "https://clientbp.ggblueshark.com/GetLoginData"
        GetLoginData_res_headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {jwt}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        try:
            r2 = requests.post(GetLoginData_resURL, headers=GetLoginData_res_headers, data=enc_data, timeout=12, verify=False)
            log(f"[INFO] GetLoginData HTTP status: {r2.status_code}", "info")
            r2.raise_for_status()
        except Exception as e:
            log("[!] GetLoginData request failed: " + str(e), "error")
            return jsonify({"success": False, "logs": logs})

        online_ip = None
        online_port = None
        if r2.status_code == 200:
            try:
                x = r2.content.hex()
                json_result = get_available_room(x)
                if json_result:
                    parsed_data_login = json.loads(json_result)
                    if '14' in parsed_data_login and 'data' in parsed_data_login['14']:
                        online_address = parsed_data_login['14']['data']
                        online_ip = online_address[:len(online_address) - 6]
                        online_port = int(online_address[len(online_address) - 5:])
                        log(f"[✓] Online IP: {online_ip}", "success")
                        log(f"[✓] Online Port: {online_port}", "success")
                    else:
                        log("[!] Could not find field 14 in parsed data", "error")
                        return jsonify({"success": False, "logs": logs})
                else:
                    log("[!] Failed to parse GetLoginData response", "error")
                    return jsonify({"success": False, "logs": logs})
            except Exception as e:
                log(f"[!] Error processing GetLoginData response: {e}", "error")
                return jsonify({"success": False, "logs": logs})
        else:
            log("[!] GetLoginData returned error: " + str(r2.status_code), "error")
            return jsonify({"success": False, "logs": logs})

        log("", "info")
        log("[4] Building final packet...", "wait")
        payload_jwt = extract_jwt_payload_dict(jwt)
        if payload_jwt is None:
            log("[!] Failed to decode JWT payload", "error")
            return jsonify({"success": False, "logs": logs})

        account_id_int = int(payload_jwt.get("account_id", 0))
        final_token_hex = build_start_packet(
            account_id=account_id_int,
            timestamp=timetamp,
            jwt=jwt,
            key=bytes.fromhex(key_hex) if key_hex else b'',
            iv=bytes.fromhex(iv_hex) if iv_hex else b''
        )
        if not final_token_hex:
            log("[!] Failed to build start packet", "error")
            return jsonify({"success": False, "logs": logs})

        log(f"[✓] Packet built successfully", "success")
        log("", "info")
        log("[5] Connecting to game server...", "wait")

        try:
            payload_bytes = bytes.fromhex(final_token_hex)
            log(f"[*] Sending packet to {online_ip}:{online_port}...", "wait")
            response = send_once(online_ip, online_port, payload_bytes, recv_timeout=5.0)
            if response:
                log(f"[✓] Got {len(response)} bytes response:", "success")
                log("", "info")
                log("=" * 80, "info")
                log("✅ Done ban", "success")
                return jsonify({"success": True, "logs": logs, "packet": final_token_hex})
            else:
                log("[!] No response from server", "error")
                return jsonify({"success": False, "logs": logs})
        except Exception as e:
            log(f"[!] Connection error: {e}", "error")
            return jsonify({"success": False, "logs": logs})

    except Exception as e:
        log(f"[!] Unexpected error: {e}", "error")
        return jsonify({"success": False, "logs": logs})

# Vercel needs the app as a variable named 'app'
# For local development, you can still run with `python app.py`
if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
