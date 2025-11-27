import os
import base64
import sys
import hashlib
import secrets
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from flask import Flask, render_template, request, jsonify, send_file, session
import io
import tempfile

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production!

class MultiLayerEncryption:
    def __init__(self):
        self.key_file = "master.key"
        self.salt_file = "encryption.salt"
        self.master_key = self.load_or_create_keys()

    def load_or_create_keys(self):
        """Generate or load encryption keys with salt"""
        if not os.path.exists(self.salt_file):
            salt = get_random_bytes(32)
            with open(self.salt_file, "wb") as f:
                f.write(salt)

        with open(self.salt_file, "rb") as f:
            salt = f.read()

        if not os.path.exists(self.key_file):
            # Generate master password (in real usage, this would be user-provided)
            master_password = get_random_bytes(32)
            master_key = PBKDF2(master_password, salt, 32, count=1000000, hmac_hash_module=hashlib.sha512)

            with open(self.key_file, "wb") as f:
                f.write(master_key)
            print("[+] Encryption keys created successfully.")
        else:
            with open(self.key_file, "rb") as f:
                master_key = f.read()

        return master_key

    def generate_derived_keys(self):
        """Generate multiple keys from master key for different layers"""
        keys = {}
        # Generate keys for different encryption layers
        keys['aes'] = hashlib.sha256(self.master_key + b'aes_layer').digest()
        keys['chacha'] = hashlib.sha256(self.master_key + b'chacha_layer').digest()
        keys['xor1'] = hashlib.sha256(self.master_key + b'xor_layer1').digest()
        keys['xor2'] = hashlib.sha256(self.master_key + b'xor_layer2').digest()
        keys['hmac'] = hashlib.sha256(self.master_key + b'hmac_key').digest()
        return keys

    def strong_xor_encrypt(self, data, key, rounds=3):
        """Enhanced XOR encryption with multiple rounds and key derivation"""
        result = bytearray(data)
        key_len = len(key)

        for round_num in range(rounds):
            # Derive round-specific key
            round_key = hashlib.sha256(key + bytes([round_num])).digest()
            for i in range(len(result)):
                # XOR with key byte and position for more complexity
                result[i] ^= round_key[i % len(round_key)]
                result[i] ^= (i * 7) & 0xFF  # Add position-based XOR

        return bytes(result)

    def strong_xor_decrypt(self, data, key, rounds=3):
        """Decrypt data encrypted with strong XOR (XOR is symmetric)"""
        return self.strong_xor_encrypt(data, key, rounds)

    def encrypt_bytes(self, data):
        """Multi-layer encryption with AES, ChaCha20, and XOR"""
        keys = self.generate_derived_keys()

        # Layer 1: XOR Encryption
        layer1 = self.strong_xor_encrypt(data, keys['xor1'])

        # Layer 2: AES-256 Encryption
        iv_aes = get_random_bytes(16)
        cipher_aes = AES.new(keys['aes'], AES.MODE_CBC, iv_aes)
        layer2 = cipher_aes.encrypt(pad(layer1, AES.block_size))

        # Layer 3: ChaCha20 Encryption
        nonce_chacha = get_random_bytes(12)
        cipher_chacha = ChaCha20.new(key=keys['chacha'], nonce=nonce_chacha)
        layer3 = cipher_chacha.encrypt(layer2)

        # Layer 4: Final XOR
        layer4 = self.strong_xor_encrypt(layer3, keys['xor2'])

        # Create HMAC for integrity verification
        hmac = hashlib.sha512(iv_aes + nonce_chacha + layer4 + keys['hmac']).digest()

        # Combine all components
        final_blob = iv_aes + nonce_chacha + layer4 + hmac

        return final_blob

    def decrypt_bytes(self, blob):
        """Decrypt multi-layer encrypted data"""
        try:
            keys = self.generate_derived_keys()

            # Extract components
            iv_aes = blob[:16]
            nonce_chacha = blob[16:28]
            encrypted_data = blob[28:-64]  # Remove HMAC
            hmac_received = blob[-64:]

            # Verify HMAC
            hmac_calculated = hashlib.sha512(iv_aes + nonce_chacha + encrypted_data + keys['hmac']).digest()
            if not secrets.compare_digest(hmac_calculated, hmac_received):
                raise ValueError("Data integrity check failed!")

            # Layer 1: Reverse Final XOR
            layer4 = self.strong_xor_decrypt(encrypted_data, keys['xor2'])

            # Layer 2: ChaCha20 Decryption
            cipher_chacha = ChaCha20.new(key=keys['chacha'], nonce=nonce_chacha)
            layer3 = cipher_chacha.decrypt(layer4)

            # Layer 3: AES Decryption
            cipher_aes = AES.new(keys['aes'], AES.MODE_CBC, iv_aes)
            layer2 = unpad(cipher_aes.decrypt(layer3), AES.block_size)

            # Layer 4: Reverse XOR
            layer1 = self.strong_xor_decrypt(layer2, keys['xor1'])

            return layer1

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def encrypt_text(self, text):
        """Encrypt text with multi-layer encryption"""
        encrypted = self.encrypt_bytes(text.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_text(self, enc_text):
        """Decrypt multi-layer encrypted text"""
        raw = base64.b64decode(enc_text)
        return self.decrypt_bytes(raw).decode('utf-8')

    def encrypt_file(self, file_data, filename):
        """Encrypt file with multi-layer encryption"""
        try:
            encrypted_data = self.encrypt_bytes(file_data)
            return encrypted_data, None
        except Exception as e:
            return None, f"File encryption failed: {str(e)}"

    def decrypt_file(self, file_data, filename):
        """Decrypt multi-layer encrypted file"""
        try:
            decrypted_data = self.decrypt_bytes(file_data)
            return decrypted_data, None
        except Exception as e:
            return None, f"File decryption failed: {str(e)}"

# Initialize the encryption system
encryptor = MultiLayerEncryption()

# HTML Template for the web interface
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureCrypt - Multi-Layer Encryption</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --secondary: #64748b;
            --success: #10b981;
            --error: #ef4444;
            --background: #f8fafc;
            --surface: #ffffff;
            --text: #1e293b;
            --border: #e2e8f0;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--background);
            color: var(--text);
            line-height: 1.6;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 40px 0 20px 0;
        }

        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 8px;
        }

        .header p {
            font-size: 1.1rem;
            color: var(--secondary);
            max-width: 600px;
            margin: 0 auto;
        }

        .card {
            background: var(--surface);
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid var(--border);
            margin-bottom: 24px;
            overflow: hidden;
        }

        .card-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            background: #f8fafc;
        }

        .card-header h2 {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text);
        }

        .card-body {
            padding: 24px;
        }

        .nav-tabs {
            display: flex;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
            border-radius: 8px 8px 0 0;
            overflow: hidden;
        }

        .nav-tab {
            padding: 16px 24px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 0.95rem;
            font-weight: 500;
            color: var(--secondary);
            transition: all 0.2s ease;
            border-bottom: 2px solid transparent;
        }

        .nav-tab:hover {
            color: var(--primary);
            background: #f8fafc;
        }

        .nav-tab.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
            background: #f1f5f9;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text);
        }

        textarea, input[type="text"], input[type="file"] {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 0.95rem;
            transition: border-color 0.2s ease;
            background: var(--surface);
        }

        textarea:focus, input[type="text"]:focus {
            border-color: var(--primary);
            outline: none;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        textarea {
            min-height: 120px;
            resize: vertical;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.9rem;
        }

        .btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.95rem;
            font-weight: 500;
            transition: all 0.2s ease;
        }

        .btn:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn-block {
            width: 100%;
        }

        .result-box {
            margin-top: 20px;
            padding: 16px;
            background: #f8fafc;
            border-radius: 8px;
            border-left: 4px solid var(--primary);
        }

        .result-box pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.85rem;
        }

        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid transparent;
        }

        .alert-success {
            background: #f0fdf4;
            color: #166534;
            border-left-color: var(--success);
        }

        .alert-error {
            background: #fef2f2;
            color: #991b1b;
            border-left-color: var(--error);
        }

        .file-info {
            margin-top: 12px;
            padding: 12px;
            background: #f8fafc;
            border-radius: 6px;
            font-size: 0.9rem;
        }

        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }

        .status-item {
            padding: 16px;
            background: #f8fafc;
            border-radius: 8px;
            border-left: 4px solid var(--primary);
        }

        .status-item h3 {
            font-size: 0.95rem;
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--text);
        }

        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }

        .status-success {
            background: #d1fae5;
            color: #065f46;
        }

        .status-error {
            background: #fee2e2;
            color: #991b1b;
        }

        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px 0;
            color: var(--secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--border);
        }

        .dev-credit {
            color: var(--primary);
            font-weight: 500;
        }

        @media (max-width: 768px) {
            .container {
                padding: 16px;
            }

            .header h1 {
                font-size: 2rem;
            }

            .nav-tabs {
                flex-direction: column;
            }

            .nav-tab {
                text-align: left;
                border-bottom: 1px solid var(--border);
                border-left: 4px solid transparent;
            }

            .nav-tab.active {
                border-left-color: var(--primary);
                border-bottom-color: var(--border);
            }

            .status-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SecureCrypt</h1>
            <p>Enterprise-grade multi-layer encryption for text and files</p>
        </div>

        <div class="card">
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="switchTab('text-encrypt')">Text Encryption</button>
                <button class="nav-tab" onclick="switchTab('text-decrypt')">Text Decryption</button>
                <button class="nav-tab" onclick="switchTab('file-encrypt')">File Encryption</button>
                <button class="nav-tab" onclick="switchTab('file-decrypt')">File Decryption</button>
                <button class="nav-tab" onclick="switchTab('system-info')">System Info</button>
            </div>

            <div class="card-body">
                <!-- Text Encryption Tab -->
                <div id="text-encrypt" class="tab-content active">
                    <div class="form-group">
                        <label for="plainText">Text to Encrypt</label>
                        <textarea id="plainText" name="plainText" placeholder="Enter sensitive text here..."></textarea>
                    </div>
                    <button class="btn btn-block" onclick="encryptText()">Encrypt Text</button>
                    <div id="textEncryptResult"></div>
                </div>

                <!-- Text Decryption Tab -->
                <div id="text-decrypt" class="tab-content">
                    <div class="form-group">
                        <label for="encryptedText">Encrypted Text</label>
                        <textarea id="encryptedText" name="encryptedText" placeholder="Paste encrypted text here..."></textarea>
                    </div>
                    <button class="btn btn-block" onclick="decryptText()">Decrypt Text</button>
                    <div id="textDecryptResult"></div>
                </div>

                <!-- File Encryption Tab -->
                <div id="file-encrypt" class="tab-content">
                    <div class="form-group">
                        <label for="fileToEncrypt">File to Encrypt</label>
                        <input type="file" id="fileToEncrypt" name="file">
                    </div>
                    <button class="btn btn-block" onclick="encryptFile()">Encrypt File</button>
                    <div id="fileEncryptResult"></div>
                </div>

                <!-- File Decryption Tab -->
                <div id="file-decrypt" class="tab-content">
                    <div class="form-group">
                        <label for="fileToDecrypt">File to Decrypt</label>
                        <input type="file" id="fileToDecrypt" name="file">
                    </div>
                    <button class="btn btn-block" onclick="decryptFile()">Decrypt File</button>
                    <div id="fileDecryptResult"></div>
                </div>

                <!-- System Info Tab -->
                <div id="system-info" class="tab-content">
                    <h3 style="margin-bottom: 16px;">System Status</h3>
                    <div class="status-grid">
                        <div class="status-item">
                            <h3>Encryption System</h3>
                            <p><strong>Master Key:</strong> <span id="masterKeyStatus" class="status-badge">Checking...</span></p>
                            <p><strong>Salt File:</strong> <span id="saltStatus" class="status-badge">Checking...</span></p>
                        </div>
                        <div class="status-item">
                            <h3>Environment</h3>
                            <p><strong>Python:</strong> <span id="pythonVersion">-</span></p>
                            <p><strong>Platform:</strong> <span id="platform">-</span></p>
                        </div>
                    </div>

                    <h3 style="margin: 24px 0 16px 0;">Security Features</h3>
                    <div class="status-grid">
                        <div class="status-item">
                            <h3>Encryption Layers</h3>
                            <ul style="padding-left: 20px; color: var(--secondary); font-size: 0.9rem;">
                                <li>AES-256 (CBC Mode)</li>
                                <li>ChaCha20 Stream Cipher</li>
                                <li>Multi-round XOR</li>
                                <li>HMAC-SHA512 Integrity</li>
                            </ul>
                        </div>
                        <div class="status-item">
                            <h3>Key Management</h3>
                            <ul style="padding-left: 20px; color: var(--secondary); font-size: 0.9rem;">
                                <li>PBKDF2 Key Derivation</li>
                                <li>Salt-based Key Generation</li>
                                <li>Layer-specific Keys</li>
                                <li>Secure Random IVs</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>SecureCrypt v1.0 | <span class="dev-credit">Dev By ForSy</span> | Enterprise Encryption Solution</p>
        </div>
    </div>

    <script>
        function switchTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });

            // Remove active class from all tabs
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // Show selected tab content
            document.getElementById(tabName).classList.add('active');

            // Add active class to clicked tab
            event.target.classList.add('active');

            // Load system info when switching to that tab
            if (tabName === 'system-info') {
                loadSystemInfo();
            }
        }

        function loadSystemInfo() {
            fetch('/system-info')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('pythonVersion').textContent = data.python_version.split(' ')[0];
                    document.getElementById('platform').textContent = data.platform;

                    const masterKeyStatus = document.getElementById('masterKeyStatus');
                    const saltStatus = document.getElementById('saltStatus');

                    masterKeyStatus.textContent = data.master_key_exists ? 'â Secured' : 'â Missing';
                    masterKeyStatus.className = data.master_key_exists ? 'status-badge status-success' : 'status-badge status-error';

                    saltStatus.textContent = data.salt_exists ? 'â Present' : 'â Missing';
                    saltStatus.className = data.salt_exists ? 'status-badge status-success' : 'status-badge status-error';
                });
        }

        function encryptText() {
            const plainText = document.getElementById('plainText').value;
            if (!plainText.trim()) {
                showAlert('textEncryptResult', 'Please enter text to encrypt', 'error');
                return;
            }

            const formData = new FormData();
            formData.append('plainText', plainText);

            fetch('/encrypt-text', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const resultHtml = `
                        <div class="alert alert-success">
                            Text encrypted successfully
                        </div>
                        <div class="result-box">
                            <strong>Encrypted Output:</strong>
                            <pre>${data.encrypted_text}</pre>
                        </div>
                    `;
                    document.getElementById('textEncryptResult').innerHTML = resultHtml;
                } else {
                    showAlert('textEncryptResult', data.error, 'error');
                }
            })
            .catch(error => {
                showAlert('textEncryptResult', 'Network error occurred', 'error');
            });
        }

        function decryptText() {
            const encryptedText = document.getElementById('encryptedText').value;
            if (!encryptedText.trim()) {
                showAlert('textDecryptResult', 'Please enter encrypted text', 'error');
                return;
            }

            const formData = new FormData();
            formData.append('encryptedText', encryptedText);

            fetch('/decrypt-text', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const resultHtml = `
                        <div class="alert alert-success">
                            Text decrypted successfully
                        </div>
                        <div class="result-box">
                            <strong>Decrypted Text:</strong>
                            <pre>${data.decrypted_text}</pre>
                        </div>
                    `;
                    document.getElementById('textDecryptResult').innerHTML = resultHtml;
                } else {
                    showAlert('textDecryptResult', data.error, 'error');
                }
            })
            .catch(error => {
                showAlert('textDecryptResult', 'Network error occurred', 'error');
            });
        }

        function encryptFile() {
            const fileInput = document.getElementById('fileToEncrypt');
            const file = fileInput.files[0];

            if (!file) {
                showAlert('fileEncryptResult', 'Please select a file', 'error');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);

            document.getElementById('fileEncryptResult').innerHTML = '<div class="alert">Encrypting file... Please wait.</div>';

            fetch('/encrypt-file', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const resultHtml = `
                        <div class="alert alert-success">
                            File encrypted successfully
                        </div>
                        <div class="file-info">
                            <p><strong>Original:</strong> ${data.original_filename}</p>
                            <p><strong>Size:</strong> ${formatFileSize(data.file_size)}</p>
                        </div>
                        <button class="btn" onclick="downloadFile('${data.download_url}', '${data.encrypted_filename}')" style="margin-top: 12px;">
                            Download Encrypted File
                        </button>
                    `;
                    document.getElementById('fileEncryptResult').innerHTML = resultHtml;
                } else {
                    showAlert('fileEncryptResult', data.error, 'error');
                }
            })
            .catch(error => {
                showAlert('fileEncryptResult', 'Network error occurred', 'error');
            });
        }

        function decryptFile() {
            const fileInput = document.getElementById('fileToDecrypt');
            const file = fileInput.files[0];

            if (!file) {
                showAlert('fileDecryptResult', 'Please select a file', 'error');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);

            document.getElementById('fileDecryptResult').innerHTML = '<div class="alert">Decrypting file... Please wait.</div>';

            fetch('/decrypt-file', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const resultHtml = `
                        <div class="alert alert-success">
                            File decrypted successfully
                        </div>
                        <div class="file-info">
                            <p><strong>Original:</strong> ${data.original_filename}</p>
                            <p><strong>Size:</strong> ${formatFileSize(data.file_size)}</p>
                        </div>
                        <button class="btn" onclick="downloadFile('${data.download_url}', '${data.decrypted_filename}')" style="margin-top: 12px;">
                            Download Decrypted File
                        </button>
                    `;
                    document.getElementById('fileDecryptResult').innerHTML = resultHtml;
                } else {
                    showAlert('fileDecryptResult', data.error, 'error');
                }
            })
            .catch(error => {
                showAlert('fileDecryptResult', 'Network error occurred', 'error');
            });
        }

        function showAlert(elementId, message, type) {
            const alertClass = type === 'error' ? 'alert-error' : 'alert-success';
            document.getElementById(elementId).innerHTML = `
                <div class="alert ${alertClass}">
                    ${message}
                </div>
            `;
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function downloadFile(url, filename) {
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // Load system info on page load if on system info tab
        document.addEventListener('DOMContentLoaded', function() {
            if (document.getElementById('system-info').classList.contains('active')) {
                loadSystemInfo();
            }
        });
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return HTML_TEMPLATE

@app.route('/encrypt-text', methods=['POST'])
def encrypt_text():
    try:
        plain_text = request.form['plainText']
        if not plain_text.strip():
            return jsonify({'success': False, 'error': 'No text provided'})

        encrypted_text = encryptor.encrypt_text(plain_text)
        return jsonify({'success': True, 'encrypted_text': encrypted_text})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/decrypt-text', methods=['POST'])
def decrypt_text():
    try:
        encrypted_text = request.form['encryptedText']
        if not encrypted_text.strip():
            return jsonify({'success': False, 'error': 'No encrypted text provided'})

        decrypted_text = encryptor.decrypt_text(encrypted_text)
        return jsonify({'success': True, 'decrypted_text': decrypted_text})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})

        file_data = file.read()
        encrypted_data, error = encryptor.encrypt_file(file_data, file.filename)

        if error:
            return jsonify({'success': False, 'error': error})

        # Store encrypted file in session for download
        session['encrypted_file'] = base64.b64encode(encrypted_data).decode('utf-8')
        session['encrypted_filename'] = file.filename + '.encrypted'

        return jsonify({
            'success': True,
            'original_filename': file.filename,
            'encrypted_filename': session['encrypted_filename'],
            'file_size': len(encrypted_data),
            'download_url': '/download-encrypted'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})

        file_data = file.read()
        decrypted_data, error = encryptor.decrypt_file(file_data, file.filename)

        if error:
            return jsonify({'success': False, 'error': error})

        # Store decrypted file in session for download
        session['decrypted_file'] = base64.b64encode(decrypted_data).decode('utf-8')

        # Determine original filename
        if file.filename.endswith('.encrypted'):
            original_name = file.filename[:-10]  # Remove .encrypted
        else:
            original_name = file.filename + '.decrypted'

        session['decrypted_filename'] = original_name

        return jsonify({
            'success': True,
            'original_filename': file.filename,
            'decrypted_filename': session['decrypted_filename'],
            'file_size': len(decrypted_data),
            'download_url': '/download-decrypted'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/download-encrypted')
def download_encrypted():
    if 'encrypted_file' not in session:
        return "No encrypted file available", 404

    file_data = base64.b64decode(session['encrypted_file'])
    filename = session.get('encrypted_filename', 'encrypted_file.encrypted')

    return send_file(
        io.BytesIO(file_data),
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )

@app.route('/download-decrypted')
def download_decrypted():
    if 'decrypted_file' not in session:
        return "No decrypted file available", 404

    file_data = base64.b64decode(session['decrypted_file'])
    filename = session.get('decrypted_filename', 'decrypted_file')

    return send_file(
        io.BytesIO(file_data),
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )

@app.route('/system-info')
def system_info():
    key_exists = os.path.exists("master.key")
    salt_exists = os.path.exists("encryption.salt")

    return jsonify({
        'python_version': sys.version,
        'platform': sys.platform,
        'master_key_exists': key_exists,
        'salt_exists': salt_exists
    })

def main():
    """Main function to run the application"""
    print("=" * 60)
    print("       SECURECRYPT - MULTI-LAYER ENCRYPTION")
    print("              Professional Web Edition")
    print("=" * 60)
    print("\nStarting web server...")
    print("Web interface available at: http://localhost:5000")
    print("Developer: ForSy")
    print("\nPress Ctrl+C to stop the server")

    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Server stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An error occurred: {str(e)}")
        sys.exit(1) 
        print