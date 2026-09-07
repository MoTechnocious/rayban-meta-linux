#!/usr/bin/env bash
#
# Pair / re-pair Ray-Ban Meta (Gen 2) glasses to a Linux PC as a Bluetooth
# audio device, using BlueZ (bluetoothctl). Works for a first-time pairing and
# for recovering the connection after a factory reset (which invalidates any
# previous bond on this PC).
#
# Usage:
#   1. Put the glasses into Bluetooth pairing mode: place them in the charging
#      case, open the lid, and hold the pairing button inside the case until the
#      LED blinks. (There is no "connect a device" option in the Meta AI app;
#      the in-case button is the method.)
#   2. Run:  GLASSES_MAC=XX:XX:XX:XX:XX:XX ./pair-glasses.sh
#      (find the MAC with:  bluetoothctl scan on   and look for "RB Meta ....")
#   3. Take the glasses OUT of the case and power them on; they will reconnect.
#
# Notes:
#   - Uses a NoInputNoOutput agent so no passkey prompt is needed on the PC.
#   - The glasses only complete a new bond while actively in pairing mode.
#   - Re-pairing this PC may drop the glasses from a phone if they do not support
#     multipoint; you can switch back from the phone afterwards.

set -uo pipefail
DEV="${GLASSES_MAC:-${1:-}}"
if [[ -z "$DEV" ]]; then
  echo "error: set GLASSES_MAC or pass the MAC as the first argument" >&2
  echo "  e.g. GLASSES_MAC=98:59:49:AA:BB:CC $0" >&2
  exit 1
fi

echo "[*] Target glasses: $DEV"
echo "[*] Removing any stale bond (safe if none exists)..."
bluetoothctl remove "$DEV" >/dev/null 2>&1 || true

echo "[*] Discovering (make sure the glasses are in pairing mode NOW)..."
timeout 10 bluetoothctl --timeout 8 scan on >/dev/null 2>&1 || true

echo "[*] Pairing..."
( echo "agent off";            sleep 1
  echo "agent NoInputNoOutput"; sleep 1
  echo "default-agent";         sleep 1
  echo "scan on";               sleep 4
  echo "pair $DEV";             sleep 16
  echo "trust $DEV";            sleep 2
  echo "connect $DEV";          sleep 10
  echo "scan off";              sleep 1
  echo "quit"
) | timeout 80 bluetoothctl 2>&1 \
  | grep -iE 'passkey|Confirm|Paired|Bonded|Connected|Failed|success|br-connection|Authentication' || true

echo
echo "=== result ==="
bluetoothctl info "$DEV" 2>/dev/null | grep -E 'Name|Paired|Bonded|Trusted|Connected' || {
  echo "device not found; ensure it is in pairing mode and re-run"
  exit 1
}

echo
echo "If Connected: no, the glasses are probably still in the case."
echo "Take them out and power on; being Trusted they should reconnect, or run:"
echo "  bluetoothctl connect $DEV"
