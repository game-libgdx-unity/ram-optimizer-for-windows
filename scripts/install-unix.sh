#!/usr/bin/env bash
# Install RAM Optimizer to run every N minutes (no daemon):
#   macOS -> a LaunchAgent;  Linux -> a crontab entry.
# Build first:  cargo build --release
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/ram-optimizer"
INTERVAL_MIN="${INTERVAL_MIN:-5}"

if [ ! -x "$BIN" ]; then
  echo "Release binary missing: $BIN"
  echo "Build it first:  cargo build --release"
  exit 1
fi
[ -f "$ROOT/config.json" ] || cp "$ROOT/config.example.json" "$ROOT/config.json"
mkdir -p "$HOME/.ram-optimizer"

case "$(uname -s)" in
  Darwin)
    PLIST="$HOME/Library/LaunchAgents/com.ram-optimizer.monitor.plist"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.ram-optimizer.monitor</string>
  <key>ProgramArguments</key><array><string>$BIN</string></array>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>StartInterval</key><integer>$((INTERVAL_MIN * 60))</integer>
  <key>StandardOutPath</key><string>$HOME/.ram-optimizer/cron.log</string>
  <key>StandardErrorPath</key><string>$HOME/.ram-optimizer/cron.log</string>
</dict></plist>
EOF
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    echo "Loaded LaunchAgent: $PLIST (every $INTERVAL_MIN min)"
    ;;
  *)
    LINE="*/$INTERVAL_MIN * * * * cd \"$ROOT\" && \"$BIN\" >> \"$HOME/.ram-optimizer/cron.log\" 2>&1"
    ( crontab -l 2>/dev/null | grep -vF "$BIN" || true; echo "$LINE" ) | crontab -
    echo "Installed crontab entry (every $INTERVAL_MIN min)."
    ;;
esac

echo "Run the dashboard with:  $BIN ui"
