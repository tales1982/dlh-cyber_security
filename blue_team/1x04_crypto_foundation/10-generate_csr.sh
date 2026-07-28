#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <common_name>" >&2
    echo "Example: $0 portal.meddefense.local" >&2
    exit 1
fi

CN="$1"
KEY_OUT="portal_key.pem"
CSR_OUT="portal.csr"
CONFIG_OUT="openssl.cnf"

cat > "$CONFIG_OUT" << EOF
[ req ]
default_bits       = 256
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = $CN
O  = MedDefense Health Systems
OU = Information Technology
L  = Springfield
ST = Illinois
C  = US

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $CN
DNS.2 = www.$CN
DNS.3 = patientportal.meddefense.local
EOF

echo "Step 1: Generating ECC P-256 private key -> $KEY_OUT"
openssl ecparam -genkey -name prime256v1 -out "$KEY_OUT"
if [[ $? -ne 0 ]]; then
    echo "Error: key generation failed" >&2
    exit 1
fi

echo "Step 2: Generating CSR -> $CSR_OUT"
openssl req -new -key "$KEY_OUT" -out "$CSR_OUT" -config "$CONFIG_OUT"
if [[ $? -ne 0 ]]; then
    echo "Error: CSR generation failed" >&2
    exit 1
fi

echo "Step 3: Inspecting generated CSR"
openssl req -text -noout -in "$CSR_OUT"

echo ""
echo "Done. Private key: $KEY_OUT | CSR: $CSR_OUT | Config used: $CONFIG_OUT"
