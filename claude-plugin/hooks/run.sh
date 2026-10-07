#!/bin/sh
# Run the KeyValet secret hook with KeyValet's own node if installed, else any node; stay silent otherwise.
NODE=/usr/local/lib/keyvalet/bin/node
[ -x "$NODE" ] || NODE=$(command -v node 2>/dev/null) || exit 0
exec "$NODE" "$(dirname "$0")/secrets.mjs" "$@"
