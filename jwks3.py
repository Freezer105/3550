from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import jwt
import datetime
import sqlite3
import os
import uuid
from argon2 import PasswordHasher

app = Flask(__name__)

# Initialize SQLite database connection
db_path = 'totally_not_my_privateKeys.db'
db_exists = os.path.exists(db_path)
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Create keys table if it doesn't exist
if not db_exists:
    cur.execute('''
        CREATE TABLE keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()

# Create users table if it doesn't exist
cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )
''')
conn.commit()

# Function to generate AES key
def generate_aes_key():
    key = os.getenv('NOT_MY_KEY')
    if not key:
        raise ValueError("Environment variable NOT_MY_KEY is not set")
    return key.encode()

# Function to encrypt data using AES
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

# Function to decrypt data using AES
def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()

# Function to generate RSA key pair
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# Function to save private key to database
def save_private_key_to_db(private_key, expiry_timestamp):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_private_key = aes_encrypt(private_pem, generate_aes_key())
    cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_private_key, expiry_timestamp))
    conn.commit()

# Function to retrieve private key from database
def retrieve_private_key_from_db():
    cur.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
    row = cur.fetchone()
    if row:
        encrypted_private_key = row[0]
        decrypted_private_key = aes_decrypt(encrypted_private_key, generate_aes_key())
        private_key = serialization.load_pem_private_key(decrypted_private_key, password=None, backend=default_backend())
        return private_key
    else:
        return None

# Function to register a new user
@app.route('/register', methods=['POST'])
def register_user():
    username = request.json.get('username')
    email = request.json.get('email')

    if not username or not email:
        return "Username and email are required", 400

    password = str(uuid.uuid4())
    ph = PasswordHasher()
    password_hash = ph.hash(password)

    try:
        cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
        conn.commit()
        return jsonify(password=password), 201
    except sqlite3.IntegrityError:
        return "Username or email already exists", 409

# Endpoint to serve JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    private_key = retrieve_private_key_from_db()
    if private_key:
        jwk = {
            "kid": "my-key-id",
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": private_key.public_key().public_numbers().n,
            "e": private_key.public_key().public_numbers().e,
            "exp": expiry_timestamp.timestamp()  # Expiry timestamp in seconds since epoch
        }
        return jsonify(keys=[jwk]), 200
    else:
        return "No valid private key found", 500

# Endpoint to authenticate and issue JWTs
@app.route('/auth', methods=['POST'])
def auth():
    username = request.json.get('username')
    password = request.json.get('password')

    # Check username and password
    cur.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    if user:
        ph = PasswordHasher()
        try:
            ph.verify(user[1], password)
        except:
            return "Authentication failed", 401
        else:
            user_id = user[0]
            cur.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request.remote_addr, user_id))
            conn.commit()

            private_key = retrieve_private_key_from_db()
            if private_key:
                now = datetime.datetime.utcnow()
                expiry_time = now + datetime.timedelta(minutes=15)
                payload = {
                    "sub": username,
                    "iat": int(now.timestamp()),
                    "exp": int(expiry_time.timestamp()),
                    "expiry_date": expiry_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "iss": "your-issuer",
                    "aud": "your-audience",
                    "kid": "my-key-id"
                }

                token = jwt.encode(payload, private_key, algorithm='RS256')
                return jsonify(jwt=token.decode('utf-8'), expiry_date=payload['expiry_date']), 200
            else:
                return "No valid private key found", 500
    else:
        return "Authentication failed", 401

if __name__ == '__main__':
    app.run(port=8080)
