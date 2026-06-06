#!/usr/bin/env bash
# Submit exploit.json (hex-encoded) to the customer-service holpy oracle.
set -euo pipefail

HOST=grilled-souffle-beside-roasted-tomato-juss.gpn24.ctf.kitctf.de
PORT=443

hex=$(python3 -c "import sys; print(open(sys.argv[1]).read().encode().hex())" \
       "${1:-$(dirname "$0")/exploit.json}")

{ printf '%s\n' "$hex"; sleep 5; } | \
  openssl s_client -quiet -connect "$HOST:$PORT" 2>/dev/null
