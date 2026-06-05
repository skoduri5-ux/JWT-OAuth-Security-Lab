from flask import Flask, request, jsonify
import jwt
import json
import base64
import hmac
import hashlib
import datetime
import uuid

app = Flask(__name__)

with open("keys/private.pem", "r") as f:
    PRIVATE_KEY = f.read()
with open("keys/public.pem", "r") as f:
    PUBLIC_KEY = f.read()

USERS = {"admin": "password123"}
USED_TOKENS = set()
ALLOWED_REDIRECTS = ["http://127.0.0.1:5000/callback"]

def get_public_key_bytes():
    """Strip PEM headers to get raw DER bytes — used as HMAC secret in confusion attack."""
    raw = "".join(PUBLIC_KEY.strip().splitlines()[1:-1])
    return base64.b64decode(raw)

def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "==")

def verify_hs256(token: str) -> dict:
    """Manually verify HS256 using the RSA public key as the HMAC secret."""
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    key_bytes = get_public_key_bytes()
    expected_sig = base64.urlsafe_b64encode(
        hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    if not hmac.compare_digest(parts[2], expected_sig):
        raise ValueError("Invalid HS256 signature")
    return json.loads(b64url_decode(parts[1]))

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if USERS.get(username) != password:
        return jsonify({"error": "invalid credentials"}), 401
    payload = {
        "user": username,
        "role": "admin",
        "jti": str(uuid.uuid4()),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return jsonify({"token": token})

@app.route("/dashboard")
def dashboard():
    auth = request.headers.get("Authorization")
    if not auth:
        return jsonify({"error": "missing token"}), 401
    token = auth.split(" ")[1]
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return jsonify({"error": "invalid token format"}), 401

        # VULNERABILITY: read alg from attacker-controlled header
        header = json.loads(b64url_decode(parts[0]))
        alg = header.get("alg", "")

        if alg.lower() == "none":
            # VULN 1: accept unsigned token
            decoded = json.loads(b64url_decode(parts[1]))

        elif alg == "HS256":
            # VULN 2: verify HS256 using RSA public key as HMAC secret
            decoded = verify_hs256(token)

        else:
            # RS256 — legitimate path
            decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])

        jti = decoded.get("jti")
        if jti and jti in USED_TOKENS:
            return jsonify({"error": "replay detected"}), 401
        if jti:
            USED_TOKENS.add(jti)
        return jsonify({"message": "welcome", "data": decoded})

    except Exception as e:
        return jsonify({"error": str(e)}), 401

EXPECTED_STATE = "secure-state-123"

@app.route("/authorize")
def authorize():
    redirect_uri = request.args.get("redirect_uri")

    if redirect_uri not in ALLOWED_REDIRECTS:
        return jsonify({"error": "invalid redirect_uri"}), 400

    code = "mock-auth-code"

    return jsonify({
        "redirect_to":
        f"{redirect_uri}?code={code}&state={EXPECTED_STATE}"
    })


@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if state != EXPECTED_STATE:
        return jsonify({
            "error": "invalid state"
        }), 401

    return jsonify({
        "received_code": code,
        "received_state": state
    })

@app.route("/token", methods=["POST"])
def token():
    code = request.json.get("code")
    if code != "mock-auth-code":
        return jsonify({"error": "bad code"}), 400
    access_token = jwt.encode(
        {"user": "victim", "scope": "read",
         "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        PRIVATE_KEY, algorithm="RS256"
    )
    return jsonify({"access_token": access_token, "token_type": "Bearer"})

@app.route("/public-key")
def public_key():
    return PUBLIC_KEY, 200, {"Content-Type": "text/plain"}

if __name__ == "__main__":
    app.run(debug=True)
