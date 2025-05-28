import os
import json
import bcrypt
import secrets
import string
import re
from base64 import urlsafe_b64encode, urlsafe_b64decode
from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__, static_folder='static')

VAULT_FILE = "vault.json"
SALT_FILE = "salt.bin"

def generate_salt():
    return secrets.token_bytes(16)

def get_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(password)

def encrypt(key: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return urlsafe_b64encode(nonce + ciphertext).decode()

def decrypt(key: bytes, enc_data: str) -> str:
    aesgcm = AESGCM(key)
    raw = urlsafe_b64decode(enc_data.encode())
    nonce = raw[:12]
    ciphertext = raw[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def load_vault():
    if not os.path.exists(VAULT_FILE):
        return None
    with open(VAULT_FILE, "r") as f:
        return json.load(f)

def save_vault(data):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def authenticate(master_password: str) -> bytes:
    if not os.path.exists(VAULT_FILE) or not os.path.exists(SALT_FILE):
        raise Exception("Vault not initialized.")
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    vault = load_vault()
    if not vault or not bcrypt.checkpw(master_password.encode(), vault["_master"].encode()):
        raise Exception("Invalid master password.")
    return get_key(master_password.encode(), salt)

def check_password_strength(password: str) -> str:
    length = len(password) >= 8
    lower = re.search(r"[a-z]", password)
    upper = re.search(r"[A-Z]", password)
    digit = re.search(r"[0-9]", password)
    symbol = re.search(r"[^A-Za-z0-9]", password)
    score = sum([length, bool(lower), bool(upper), bool(digit), bool(symbol)])
    if score == 5:
        return "Strong"
    elif score >= 3:
        return "Medium"
    else:
        return "Weak"

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

# Routes

@app.route('/initialize', methods=['POST'])
def initialize():
    data = request.json
    master_password = data.get('master_password')
    if not master_password:
        return jsonify({"message": "Master password required"}), 400
    if os.path.exists(VAULT_FILE) or os.path.exists(SALT_FILE):
        return jsonify({"message": "Vault already initialized"}), 400
    salt = generate_salt()
    key = get_key(master_password.encode(), salt)
    hashed_master = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt()).decode()
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    vault = {"_master": hashed_master, "entries": {}}
    save_vault(vault)
    return jsonify({"message": "Vault initialized successfully"})

@app.route('/add', methods=['POST'])
def add_password():
    data = request.json
    master_password = data.get('master_password')
    site = data.get('site')
    password = data.get('password')
    if not all([master_password, site, password]):
        return jsonify({"message": "Missing fields"}), 400
    try:
        key = authenticate(master_password)
        vault = load_vault()
        vault["entries"][site] = encrypt(key, password)
        save_vault(vault)
        return jsonify({"message": f"Password for {site} added"})
    except Exception as e:
        return jsonify({"message": str(e)}), 400

@app.route('/retrieve', methods=['POST'])
def retrieve_password():
    data = request.json
    master_password = data.get('master_password')
    site = data.get('site')
    if not all([master_password, site]):
        return jsonify({"message": "Missing fields"}), 400
    try:
        key = authenticate(master_password)
        vault = load_vault()
        encrypted = vault["entries"].get(site)
        if not encrypted:
            return jsonify({"message": "No password found for this site"}), 404
        decrypted = decrypt(key, encrypted)
        return jsonify({"password": decrypted})
    except Exception as e:
        return jsonify({"message": str(e)}), 400

@app.route('/generate', methods=['GET'])
def generate():
    pwd = generate_password()
    strength = check_password_strength(pwd)
    return jsonify({"password": pwd, "strength": strength})

@app.route('/strength', methods=['POST'])
def strength():
    data = request.json
    pwd = data.get('password')
    if not pwd:
        return jsonify({"message": "Password required"}), 400
    strength = check_password_strength(pwd)
    return jsonify({"strength": strength})

# Serve static HTML pages
@app.route('/')
def root():
    return app.send_static_file('index.html')

@app.route('/<path:path>')
def static_proxy(path):
    # serve static files (html, css, js)
    return send_from_directory('static', path)

if __name__ == '__main__':
    app.run(debug=True)
