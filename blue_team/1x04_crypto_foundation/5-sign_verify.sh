#!/bin/bash

usage() {
    echo "Usage: $0 sign <file_path> <private_key_path>" >&2
    echo "       $0 verify <file_path> <signature_path> <public_key_path>" >&2
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

MODE="$1"

case "$MODE" in
    sign)
        if [[ $# -ne 3 ]]; then
            usage
        fi
        FILE_PATH="$2"
        PRIVATE_KEY="$3"

        if [[ ! -f "$FILE_PATH" ]]; then
            echo "Error: file not found: $FILE_PATH" >&2
            exit 1
        fi
        if [[ ! -f "$PRIVATE_KEY" ]]; then
            echo "Error: private key not found: $PRIVATE_KEY" >&2
            exit 1
        fi

        SIG_PATH="${FILE_PATH}.sig"
        openssl dgst -sha256 -sign "$PRIVATE_KEY" -out "$SIG_PATH" "$FILE_PATH"
        echo "Signed '$FILE_PATH' -> '$SIG_PATH'"
        ;;
    verify)
        if [[ $# -ne 4 ]]; then
            usage
        fi
        FILE_PATH="$2"
        SIG_PATH="$3"
        PUBLIC_KEY="$4"

        if [[ ! -f "$FILE_PATH" ]]; then
            echo "Error: file not found: $FILE_PATH" >&2
            exit 1
        fi
        if [[ ! -f "$SIG_PATH" ]]; then
            echo "Error: signature file not found: $SIG_PATH" >&2
            exit 1
        fi
        if [[ ! -f "$PUBLIC_KEY" ]]; then
            echo "Error: public key not found: $PUBLIC_KEY" >&2
            exit 1
        fi

        openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIG_PATH" "$FILE_PATH"
        ;;
    *)
        usage
        ;;
esac
