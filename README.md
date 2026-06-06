# JWT & OAuth Security Lab

A Flask-based security lab demonstrating JWT and OAuth authentication vulnerabilities and their mitigations.

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
