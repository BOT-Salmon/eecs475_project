# CBC Padding Oracle Demo

This folder contains a simple demo on **CBC padding oracle attacks**.

## Files

- `padding_oracle_demo.py`: AES-CBC + PKCS#7 vulnerable system, padding oracle, attack script, and AES-GCM comparison.
- `requirements.txt`: Python dependency list.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python padding_oracle_demo.py
```

You can also choose a custom message:

```bash
python padding_oracle_demo.py --message "Attack at dawn."
```

## What the script demonstrates

1. A toy AES-CBC encryption system using PKCS#7 padding.
2. A deliberately insecure oracle that reveals only whether padding is valid.
3. A byte-by-byte attack that recovers plaintext without the secret key.
4. A comparison with AES-GCM to illustrate why authenticated encryption blocks this style of attack.
