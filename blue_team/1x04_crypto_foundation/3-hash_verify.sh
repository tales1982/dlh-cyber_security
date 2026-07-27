#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <file_path> <expected_sha256_hash>" >&2
    exit 1
fi

FILE_PATH="$1"
EXPECTED_HASH="$2"

if [[ ! -f "$FILE_PATH" ]]; then
    echo "Error: file not found: $FILE_PATH" >&2
    exit 1
fi

ACTUAL_HASH=$(sha256sum "$FILE_PATH" | awk '{print $1}')

if [[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $EXPECTED_HASH got $ACTUAL_HASH"
    exit 1
fi
