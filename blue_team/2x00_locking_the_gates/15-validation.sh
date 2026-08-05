#!/bin/bash
set -euo pipefail
OUT_JSON="validation_results.json"
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1