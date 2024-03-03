from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import datetime


app = Flask(__name__)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Calculate expiry timestamp i used 30 days as an example
expiry_timestamp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)



# Create a JWKS with expiry timestamp
jwk = {
    "kid": "my-key-id",
    "alg": "RS256",
    "kty": "RSA",
    "use": "sig",
    "n": public_key.public_numbers().n,
    "e": public_key.public_numbers().e,
    "exp": expiry_timestamp.timestamp()  # Expiry timestamp in seconds since epoch
}

# Endpoint to serve JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    return jsonify(keys=[jwk])

# Endpoint to authenticate and issue JWTs
@app.route('/auth', methods=['POST'])
def auth():
    username = request.json.get('username')
    password = request.json.get('password')
    expired = request.args.get('expired')  

    # Check username and password (mock authentication)
    if username == "timmy" and password == "timmy123":
        # Generate a JWT with the current key
        now = datetime.datetime.utcnow()
        expiry_time = now + datetime.timedelta(minutes=15)
        payload = {
            "sub": username,
            "iat": int(now.timestamp()),
            "exp": int(expiry_time.timestamp()),
            "expiry_date": expiry_time.strftime("%Y-%m-%d %H:%M:%S"),  # Include expiry date in response
            "iss": "your-issuer",
            "aud": "your-audience",
            "kid": "my-key-id"
        }

        # Check if 'expired' query parameter appears
        if expired:
            # Generate a JWT with an expired key pair and expiry
            expired_expiry_time = now - datetime.timedelta(minutes=15)  # Expired expiry
            payload['exp'] = int(expired_expiry_time.timestamp())
            token = jwt.encode(payload, private_pem, algorithm='RS256')
            return jsonify(jwt=token.decode('utf-8'), expiry_date=payload['expiry_date'])
        else:
            token = jwt.encode(payload, private_pem, algorithm='RS256')
            return jsonify(jwt=token.decode('utf-8'), expiry_date=payload['expiry_date'])

    return "Authentication failed", 401



if __name__ == '__main__':
    app.run(port=8080)
