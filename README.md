# JWT & OAuth Security Lab

I built a Flask-based JWT and OAuth security lab to demonstrate common authentication vulnerabilities and their mitigations.

In the JWT section, I demonstrated:

alg:none attack: The server trusted the JWT header and accepted tokens with alg=none, allowing an attacker to remove the signature completely and forge a token with arbitrary claims such as role=admin.

RS256 → HS256 algorithm confusion: The server accepted both RS256 and HS256 algorithms. An attacker could obtain the public key and misuse it as an HMAC secret to create a forged HS256 token that the server incorrectly trusted.

Replay attack: A captured valid JWT could be reused multiple times because the server did not track token usage. I mitigated this using a unique jti value and replay detection.

In the OAuth section, I demonstrated:

Redirect URI abuse: The authorization endpoint accepted arbitrary redirect URIs, allowing authorization codes to be sent to attacker-controlled domains.
OAuth CSRF (missing state validation): The callback endpoint accepted any state value instead of validating it against the original OAuth request, allowing session confusion and CSRF attacks.

I then implemented security controls including strict RS256 validation, replay protection, redirect URI allowlisting, and OAuth state validation.
## Features

- JWT Authentication using RS256
- OAuth Authorization Flow Simulation
- Replay Protection using JTI
- Redirect URI Validation
- OAuth State Validation

## Vulnerabilities Demonstrated

### JWT

- alg:none Bypass
- RS256 → HS256 Algorithm Confusion
- Token Replay Attack

### OAuth

- Redirect URI Abuse
- OAuth CSRF (Missing State Validation)

## Mitigations

- Strict RS256 Validation
- Replay Detection
- Redirect URI Allowlisting
- OAuth State Validation

## Project Structure

```text
app.py
none_attack.py
attack_hs256_confusion.py
replay_attack.py
attack_oauth_csrf.py
keys/


## Run

## Create virtual environment:

python3 -m venv venv
source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Start server:

python3 app.py
