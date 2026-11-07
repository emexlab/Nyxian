#!/bin/sh
URL="${NX_TRUSTSTORE_URL:-https://emexlabs.org/switzach/truststore/truststore.plist}"
SOURCE="${SRCROOT}/Shared/TrustStore/truststore.plist"
BUNDLED="${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/Shared/TrustStore/truststore.plist"

work=$(mktemp -d "${TMPDIR:-/tmp}/nxtruststore.XXXXXX") || { echo "note: TrustStore not updated: no temporary folder"; exit 0; }
trap 'rm -rf "$work"' EXIT

skip() {
    echo "note: TrustStore not updated: $1"
    exit 0
}

version() {
    [ -f "$1" ] || return 0
    [ "$(plutil -extract format raw -o - "$1" 2>/dev/null)" = 1 ] || return 0
    plutil -extract payload raw -o - "$1" 2>/dev/null | base64 -D > "$work/payload" 2>/dev/null || return 0
    plutil -extract version raw -o - "$work/payload" 2>/dev/null
}

curl -fsSL --max-time 20 --retry 1 -o "$work/truststore.plist" "$URL" 2>/dev/null || skip "couldn't download $URL"
new=$(version "$work/truststore.plist")
case "$new" in
    '' | *[!0-9]*) skip "$URL isn't a TrustStore" ;;
esac

have=$(version "$BUNDLED")
[ -n "$have" ] || have=$(version "$SOURCE")
case "$have" in
    '' | *[!0-9]*) have=0 ;;
esac
[ "$new" -ge "$have" ] || skip "the published one is version $new, older than the bundled $have"

mkdir -p "$(dirname "$BUNDLED")" && cp "$work/truststore.plist" "$BUNDLED" || skip "couldn't write $BUNDLED"
mkdir -p "$(dirname "$SOURCE")" && cp "$work/truststore.plist" "$SOURCE" 2>/dev/null
echo "note: TrustStore version $new bundled (the app had $have)"
