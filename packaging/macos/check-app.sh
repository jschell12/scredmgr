#!/bin/bash
# Check a built scredmgr.app: check-app.sh <path/to/scredmgr.app> <bundle id>
#
# macOS Local Network Privacy only prompts for, and only remembers a grant
# for, a process it can attribute to an app bundle. Each check below is a way
# the bundle can exist and still not be attributable, or not run at all.
set -uo pipefail
app="${1:?usage: check-app.sh <app> <bundle id>}"
want_id="${2:?usage: check-app.sh <app> <bundle id>}"
plist="$app/Contents/Info.plist"
fail=0
bad() { echo "check-app: $*" >&2; fail=1; }
key() { /usr/libexec/PlistBuddy -c "Print :$1" "$plist" 2>/dev/null; }

[[ -d "$app" ]] || { echo "check-app: no bundle at $app" >&2; exit 1; }
[[ -f "$plist" ]] && plutil -lint -s "$plist" >/dev/null 2>&1 \
  || { echo "check-app: $plist missing or not a valid plist" >&2; exit 1; }

id="$(key CFBundleIdentifier)"
[[ "$id" == "$want_id" ]] || bad "CFBundleIdentifier is '${id}', want '$want_id'"
exe="$(key CFBundleExecutable)"
[[ -n "$exe" && -x "$app/Contents/MacOS/$exe" ]] \
  || bad "CFBundleExecutable '${exe}' is not an executable in Contents/MacOS"
[[ -n "$(key NSLocalNetworkUsageDescription)" ]] \
  || bad "NSLocalNetworkUsageDescription is missing or empty (the prompt needs it)"
[[ "$(key LSUIElement)" == "true" ]] || bad "LSUIElement is not true (would show a Dock icon)"

if ! codesign --verify --strict "$app" 2>/dev/null; then
  bad "codesign --verify --strict fails (re-sign the bundle, not just the binary)"
else
  sig="$(codesign -dv "$app" 2>&1)"
  grep -qx "Identifier=$want_id" <<<"$sig" || bad "signing identifier is not $want_id"
  grep -q '^Info.plist entries=' <<<"$sig" || bad "signature does not bind Info.plist"
fi

[[ $fail -eq 0 ]] && echo "check-app: OK $app ($want_id)"
exit $fail
