#!/usr/bin/env bash

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

# --- Ensure log directory exists and is writable ---
echo "Setting up logging..."
LOG_DIR="${LOG_DIR:-/app/logs}"
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Test if we can write to the log directory
if touch "$LOG_DIR/.test_write" 2>/dev/null; then
  rm -f "$LOG_DIR/.test_write"
  echo "Log directory $LOG_DIR is writable"
else
  echo "WARNING: Cannot write to log directory $LOG_DIR, will use fallback"
fi

# --- Start the server ---
echo "Starting server..."
exec gunicorn -b 0.0.0.0:5000 server:app

