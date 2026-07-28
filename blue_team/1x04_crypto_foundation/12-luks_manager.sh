#!/bin/bash

usage() {
    echo "Usage: $0 create <volume_file> <size_MB> <mapper_name>" >&2
    echo "       $0 open <volume_file> <mapper_name> <mount_point>" >&2
    echo "       $0 close <mapper_name> <mount_point>" >&2
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

MODE="$1"

if ! command -v cryptsetup >/dev/null 2>&1; then
    echo "Error: cryptsetup is not installed. Install it with 'sudo apt-get install cryptsetup'." >&2
    exit 1
fi

case "$MODE" in
    create)
        if [[ $# -ne 4 ]]; then
            usage
        fi
        VOLUME_FILE="$2"
        SIZE_MB="$3"
        MAPPER_NAME="$4"

        if [[ -f "$VOLUME_FILE" ]]; then
            echo "Error: $VOLUME_FILE already exists, refusing to overwrite." >&2
            exit 1
        fi

        echo "Step 1: Allocating ${SIZE_MB}MB volume file at $VOLUME_FILE"
        dd if=/dev/zero of="$VOLUME_FILE" bs=1M count="$SIZE_MB" status=progress
        if [[ $? -ne 0 ]]; then
            echo "Error: failed to allocate volume file" >&2
            exit 1
        fi

        echo "Step 2: Formatting $VOLUME_FILE with LUKS"
        sudo cryptsetup luksFormat "$VOLUME_FILE"
        if [[ $? -ne 0 ]]; then
            echo "Error: luksFormat failed" >&2
            exit 1
        fi

        echo "Step 3: Opening the new LUKS volume as $MAPPER_NAME"
        sudo cryptsetup luksOpen "$VOLUME_FILE" "$MAPPER_NAME"
        if [[ $? -ne 0 ]]; then
            echo "Error: luksOpen failed" >&2
            exit 1
        fi

        echo "Step 4: Creating ext4 filesystem on /dev/mapper/$MAPPER_NAME"
        sudo mkfs.ext4 "/dev/mapper/$MAPPER_NAME"
        if [[ $? -ne 0 ]]; then
            echo "Error: mkfs.ext4 failed" >&2
            exit 1
        fi

        echo "Step 5: Closing the volume ($MAPPER_NAME) until it is next opened"
        sudo cryptsetup luksClose "$MAPPER_NAME"
        echo "Volume created: $VOLUME_FILE (mapper name: $MAPPER_NAME)"
        ;;
    open)
        if [[ $# -ne 4 ]]; then
            usage
        fi
        VOLUME_FILE="$2"
        MAPPER_NAME="$3"
        MOUNT_POINT="$4"

        if [[ ! -f "$VOLUME_FILE" ]]; then
            echo "Error: volume file not found: $VOLUME_FILE" >&2
            exit 1
        fi

        echo "Opening $VOLUME_FILE as /dev/mapper/$MAPPER_NAME"
        sudo cryptsetup luksOpen "$VOLUME_FILE" "$MAPPER_NAME"
        if [[ $? -ne 0 ]]; then
            echo "Error: luksOpen failed" >&2
            exit 1
        fi

        mkdir -p "$MOUNT_POINT"
        echo "Mounting /dev/mapper/$MAPPER_NAME at $MOUNT_POINT"
        sudo mount "/dev/mapper/$MAPPER_NAME" "$MOUNT_POINT"
        if [[ $? -ne 0 ]]; then
            echo "Error: mount failed" >&2
            sudo cryptsetup luksClose "$MAPPER_NAME"
            exit 1
        fi
        echo "Volume open and mounted at $MOUNT_POINT"
        ;;
    close)
        if [[ $# -ne 3 ]]; then
            usage
        fi
        MAPPER_NAME="$2"
        MOUNT_POINT="$3"

        echo "Unmounting $MOUNT_POINT"
        sudo umount "$MOUNT_POINT"
        if [[ $? -ne 0 ]]; then
            echo "Error: umount failed (is the mount point busy?)" >&2
            exit 1
        fi

        echo "Closing /dev/mapper/$MAPPER_NAME"
        sudo cryptsetup luksClose "$MAPPER_NAME"
        if [[ $? -ne 0 ]]; then
            echo "Error: luksClose failed" >&2
            exit 1
        fi
        echo "Volume unmounted and closed"
        ;;
    *)
        usage
        ;;
esac
