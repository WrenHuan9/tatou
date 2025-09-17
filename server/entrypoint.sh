#!/usr/bin/env bash

if [[ -z "${FLAG_1:-}" ]]; then
  echo "WARNING: FLAG_1 is not set"
fi

# --- Replace placeholder in /app/src/flag ---
if [[ -f "/app/src/flag" ]]; then
  if grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/app/src/flag"; then
    echo "Replacing placeholder in flag with $FLAG_1"
    sed -i "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_1}/g" /app/src/flag
  fi
else
  echo "WARNING: /app/src/flag not found, skipping"
fi

if [[ -z "${FLAG_2:-}" ]]; then
  echo "WARNING: FLAG_2 is not set"
fi

# --- Replace placeholder in /app/flag ---
if [[ -f "/app/flag" ]]; then
  if grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/app/flag"; then
    echo "Replacing placeholder in flag with $FLAG_2"
    sed -i "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_2}/g" /app/flag
  fi
else
  echo "WARNING: /app/flag not found, skipping"
fi

# --- Start the server ---
echo "Starting server..."
exec gunicorn -b 0.0.0.0:5000 server:app

