#!/usr/bin/env bash
# macos_hotspot_safe.sh
# 2025/09/26 Anthony Chambet
# Usage: sudo ./macos_hotspot_safe.sh start|stop|status
#
# - Detects Wi-Fi interface and uplink automatically on macOS
# - Uses AppleScript GUI scripting to toggle Internet Sharing and set SSID/password (best-effort)
# - Saves a small JSON state file for rollback info
#
# IMPORTANT:
# - You MUST allow Terminal (or your shell app) in System Preferences -> Security & Privacy -> Privacy -> Accessibility
# - AppleScript GUI elements differ across macOS versions; if AppleScript fails, follow the manual steps printed by the script.

set -eu

ACTION="${1:-status}"
STATE_FILE="/tmp/macos_hotspot_state.json"
HOTSPOT_SSID_DEFAULT="HOTSPOT_ANTH"
HOTSPOT_PASS_DEFAULT=""    # empty = generated automatically

# Utility: JSON-safe echo
json_escape() { python3 -c "import json,sys; print(json.dumps(sys.stdin.read().strip()))"; }

# Detect wifi interface (hardware port "Wi-Fi")
detect_wifi_iface() {
  # networksetup lists hardware ports -> find Device for "Wi-Fi" or "AirPort"
  local wifi_dev
  wifi_dev=$(networksetup -listallhardwareports 2>/dev/null | awk '/Wi-?Fi|AirPort/{getline; print $2; exit}')
  if [[ -z "$wifi_dev" ]]; then
	# fallback: guess en0 or en1 if exists
	for dev in en0 en1 en2; do
	  if /sbin/ifconfig "$dev" >/dev/null 2>&1; then
		echo "$dev"
		return 0
	  fi
	done
	echo ""  # not found
  else
	echo "$wifi_dev"
  fi
}

# Detect uplink interface (interface used for default route)
detect_uplink_iface() {
  # route get default returns interface
  local iface
  iface=$(route get default 2>/dev/null | awk '/interface: /{print $2; exit}')
  if [[ -z "$iface" ]]; then
	# fallback via netstat
	iface=$(netstat -rn | awk '/^default/{print $NF; exit}')
  fi
  echo "${iface:-}"
}

# Generate a random strong passphrase
generate_password() {
  # 16 chars base64-like
  LC_ALL=C tr -dc 'A-Za-z0-9!@#$%\-_' </dev/urandom | head -c 16 || true
}

# Check whether Internet Sharing appears enabled (best-effort)
is_internet_sharing_active() {
  # older/newer macOS maintain com.apple.nat.plist; check NAT Enabled flag
  if /usr/libexec/PlistBuddy -c "Print :NAT:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist >/dev/null 2>&1; then
	return 0
  fi
  # fallback: check sharing pref pane via defaults read (may vary across macOS versions)
  local val
  val=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null || true)
  if [[ -n "$val" ]]; then return 0; fi
  return 1
}

save_state() {
  local ssid="$1" pass="$2" wifi_if="$3" uplink_if="$4"
  cat > "$STATE_FILE" <<EOF
{
  "timestamp":"$(date --iso-8601=seconds)",
  "ssid":"$ssid",
  "password":"$pass",
  "wifi_if":"$wifi_if",
  "uplink_if":"$uplink_if",
  "sharing_active":"$( (is_internet_sharing_active && echo true) || echo false)"
}
EOF
  echo "Saved state -> $STATE_FILE"
}

start_hotspot() {
  local WIFI_IFACE UPLINK_IFACE SSID PASS

  WIFI_IFACE=$(detect_wifi_iface)
  UPLINK_IFACE=$(detect_uplink_iface)
  SSID="${HOTSPOT_SSID_DEFAULT}"
  PASS="${HOTSPOT_PASS_DEFAULT}"

  if [[ -z "$WIFI_IFACE" ]]; then
	echo "⚠️  Could not detect Wi-Fi interface automatically. Aborting. (Try: networksetup -listallhardwareports)"
	exit 1
  fi

  if [[ -z "$UPLINK_IFACE" ]]; then
	echo "⚠️  Could not detect uplink interface (default route). Proceeding — macOS will still let you choose which interface to share from in the UI."
	UPLINK_IFACE="(unknown)"
  fi

  if [[ -z "$PASS" ]]; then
	PASS=$(generate_password)
	echo "Generated hotspot password: $PASS"
  fi

  echo "Starting hotspot with:"
  echo "  Wi-Fi iface : $WIFI_IFACE"
  echo "  Uplink iface: $UPLINK_IFACE"
  echo "  SSID         : $SSID"
  echo "  PASSWORD     : (hidden)"
  save_state "$SSID" "$PASS" "$WIFI_IFACE" "$UPLINK_IFACE"

  # AppleScript: open Sharing pref pane, set options, enable Internet Sharing
  # The UI element names and structure vary across macOS versions.
  # This script tries in a tolerant way: click Options… if available, set SSID/password, then toggle Internet Sharing row checkbox.
  /usr/bin/osascript <<APPLESCRIPT || {
	echo "AppleScript failed — please ensure Terminal is allowed in Accessibility and retry. Manual steps provided below."
	echo "Manual: System Preferences → Sharing → Internet Sharing → Options… → set network name and password, then check Internet Sharing."
	exit 1
  }
  tell application "System Preferences"
	reveal anchor "InternetSharing" of pane id "com.apple.preferences.sharing"
	activate
  end tell

  -- small helper to click Options and set SSID/password if present
  tell application "System Events"
	-- wait for the Sharing window to appear
	repeat with i from 1 to 8
	  if (exists window 1 of process "System Preferences") then exit repeat
	  delay 0.4
	end repeat
	tell process "System Preferences"
	  delay 0.6
	  try
		-- click "Options…" button if present
		if (exists button "Options…" of window 1) then
		  click button "Options…" of window 1
		  delay 0.6
		  -- set SSID in text field 1 of sheet 1
		  try
			set value of text field 1 of sheet 1 of window 1 to "$SSID"
			-- attempt to set security popup to "WPA2 Personal" if present
			try
			  -- sometimes popup indexes differ; just try to set value
			  set value of pop up button 1 of sheet 1 of window 1 to "WPA2 Personal"
			end try
			-- password field often is text field 2
			set value of text field 2 of sheet 1 of window 1 to "$PASS"
			delay 0.2
			-- click OK
			try
			  click button "OK" of sheet 1 of window 1
			end try
		  end try
		end if
	  on error e
		-- ignore: options dialog might not be present on some macOS versions
	  end try

	  delay 0.4
	  -- find the "Internet Sharing" row and toggle its checkbox
	  try
		set found to false
		if (exists table 1 of scroll area 1 of window 1) then
		  set theRows to rows of table 1 of scroll area 1 of window 1
		  repeat with r in theRows
			try
			  if (value of static text 1 of r) contains "Internet Sharing" then
				-- click checkbox 1 of that row (toggle on)
				click checkbox 1 of r
				set found to true
				exit repeat
			  end if
			end try
		  end repeat
		end if
		if not found then
		  -- fallback: try to click a checkbox whose description contains "Internet Sharing"
		  try
			click checkbox 1 of window 1
		  end try
		end if
	  end try
	  delay 1.0
	end tell
  end tell

  -- give macOS a moment to apply Internet Sharing
  delay 2.0

  -- quit prefs
  tell application "System Preferences" to quit
APPLESCRIPT

  echo "If AppleScript succeeded, Internet Sharing should be active. Use 'arp -a' to list clients or open Wireshark on the created bridge interface (bridge100 or en0/en1)."
}

stop_hotspot() {
  echo "Stopping hotspot (attempting to uncheck Internet Sharing)..."
  if [[ -f "$STATE_FILE" ]]; then
	echo "State file exists: $STATE_FILE"
	cat "$STATE_FILE"
  else
	echo "No state file found; will attempt to toggle Internet Sharing off via UI."
  fi

  /usr/bin/osascript <<APPLESCRIPT || {
	echo "AppleScript failed to toggle; please disable Internet Sharing manually: System Preferences → Sharing → uncheck Internet Sharing."
	exit 1
  }
  tell application "System Preferences"
	reveal anchor "InternetSharing" of pane id "com.apple.preferences.sharing"
	activate
  end tell
  tell application "System Events"
	tell process "System Preferences"
	  delay 0.6
	  try
		if (exists table 1 of scroll area 1 of window 1) then
		  set theRows to rows of table 1 of scroll area 1 of window 1
		  repeat with r in theRows
			try
			  if (value of static text 1 of r) contains "Internet Sharing" then
				-- if checked, click to uncheck
				try
				  if (value of checkbox 1 of r as boolean) is true then click checkbox 1 of r
				end try
				exit repeat
			  end if
			end try
		  end repeat
		end if
	  end try
	  delay 0.6
	end tell
  end tell
  tell application "System Preferences" to quit
APPLESCRIPT

  echo "Stopped (or attempted to stop) Internet Sharing. If you face residual interface changes, a reboot will fully restore defaults."
  rm -f "$STATE_FILE" || true
}

status() {
  echo "== macOS Hotspot status =="
  echo "- Detected Wi-Fi interface: $(detect_wifi_iface || true)"
  echo "- Detected uplink interface: $(detect_uplink_iface || true)"
  echo "- Internet Sharing flag (best-effort): $( (is_internet_sharing_active && echo "probably ON") || echo "probably OFF")"
  if [[ -f "$STATE_FILE" ]]; then
	echo "Saved state:"
	cat "$STATE_FILE"
  fi
  echo "Useful commands:"
  echo "  - arp -a           # list clients (after hotspot active)"
  echo "  - ifconfig         # check bridge100 / en0 / en1"
  echo "  - open /System/Library/PreferencePanes/Sharing.prefPane"
}

case "$ACTION" in
  start) start_hotspot ;;
  stop) stop_hotspot ;;
  status) status ;;
  *) echo "Usage: $0 start|stop|status" ; exit 1 ;;
esac
