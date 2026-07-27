#!/bin/bash

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <input_file> <output_file> <mode: cbc|gcm>" >&2
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"
MODE="$3"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: input file not found: $INPUT_FILE" >&2
    exit 1
fi

if [[ -z "${MEDDEFENSE_ENC_PASS:-}" ]]; then
    echo "Error: set the MEDDEFENSE_ENC_PASS environment variable with the encryption passphrase before running this script." >&2
    echo "Example: MEDDEFENSE_ENC_PASS='your-passphrase' $0 $INPUT_FILE $OUTPUT_FILE $MODE" >&2
    exit 1
fi

case "$MODE" in
    cbc)
        openssl enc -aes-256-cbc -pbkdf2 -salt \
            -in "$INPUT_FILE" -out "$OUTPUT_FILE" \
            -pass env:MEDDEFENSE_ENC_PASS
        ;;
    gcm)
        # openssl's `enc` subcommand does not support AEAD ciphers (confirmed
        # directly: `openssl enc -aes-256-gcm ...` fails with "AEAD ciphers
        # not supported", even though aes-256-gcm is a registered cipher --
        # `enc` was never built to manage the authentication tag GCM
        # produces). Python's `cryptography` library is used here instead,
        # since it exposes AES-GCM directly with correct tag handling.
        if ! command -v python3 >/dev/null 2>&1; then
            echo "Error: python3 is required for GCM mode (openssl enc does not support AEAD ciphers)." >&2
            exit 1
        fi
        MEDDEFENSE_ENC_PASS="$MEDDEFENSE_ENC_PASS" python3 - "$INPUT_FILE" "$OUTPUT_FILE" <<'PYEOF'
import os
import sys
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

input_path, output_path = sys.argv[1], sys.argv[2]
passphrase = os.environ["MEDDEFENSE_ENC_PASS"].encode()

with open(input_path, "rb") as f:
    data = f.read()

# Derive a 256-bit key from the passphrase (PBKDF2, matching the -pbkdf2
# approach used for CBC mode above, so both modes are salted/stretched).
salt = os.urandom(16)
key = hashlib.pbkdf2_hmac("sha256", passphrase, salt, 600000, dklen=32)

aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, data, None)

with open(output_path, "wb") as f:
    f.write(b"MDGCM1" + salt + nonce + ciphertext)
PYEOF
        ;;
    *)
        echo "Error: mode must be 'cbc' or 'gcm', got '$MODE'" >&2
        exit 1
        ;;
esac

echo "Encrypted '$INPUT_FILE' -> '$OUTPUT_FILE' using AES-256-$(echo "$MODE" | tr '[:lower:]' '[:upper:]')"
