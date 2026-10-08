#!/bin/sh
# Run the KeyValet secret hook: prefer the installed kv-hook binary (no Node dependency);
# fall back to the legacy node+secrets.mjs path for installs that predate kv-hook; stay silent otherwise.
HOOK=/usr/local/lib/keyvalet/bin/kv-hook
if [ -x "$HOOK" ]; then
  exec "$HOOK" "$@"
fi
NODE=$(command -v node 2>/dev/null) || exit 0
exec "$NODE" "$(dirname "$0")/secrets.mjs" "$@"
