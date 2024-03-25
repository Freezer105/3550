from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import datetime
import sqlite3
import os

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
    cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_pem, expiry_timestamp))
    conn.commit()

# Function to retrieve private key from database
def retrieve_private_key_from_db():
    cur.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
    row = cur.fetchone()
    if row:
        private_key_pem = row[0]
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        return private_key
    else:
        return None

# Generate and save private keys if not exists
if not db_exists:
    private_key = generate_rsa_keypair()
    expiry_timestamp = int((datetime.datetime.utcnow() + datetime.timedelta(days=30)).timestamp())
    save_private_key_to_db(private_key, expiry_timestamp)

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
    expired = request.args.get('expired')

    # Check username and password (mock authentication)
    if username == "timmy" and password == "timmy123":
        # Retrieve private key from the database
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

            # Check if 'expired' query parameter appears
            if expired:
                expired_expiry_time = now - datetime.timedelta(minutes=15)
                payload['exp'] = int(expired_expiry_time.timestamp())

            # Sign JWT with private key and return
            token = jwt.encode(payload, private_key, algorithm='RS256')
            return jsonify(jwt=token.decode('utf-8'), expiry_date=payload['expiry_date']), 200
        else:
            return "No valid private key found", 500
    else:
        return "Authentication failed", 401

if __name__ == '__main__':
    app.run(port=8080)
