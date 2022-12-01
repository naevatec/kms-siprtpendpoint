#!/bin/bash

# Aux function: set value to a given parameter
function set_parameter() {
    # Assignments fail if any argument is missing (set -o nounset)
    local FILE="$1"
    local PARAM="$2"
    local VALUE="$3"

    local COMMENT=";"  # Kurento .ini files use ';' for comment lines
    local REGEX="^${COMMENT}?\s*${PARAM}=.*"

    if grep --extended-regexp -q "$REGEX" "$FILE"; then
        sed --regexp-extended -i "s|${REGEX}|${PARAM}=${VALUE}|" "$FILE"
    else
        echo "${PARAM}=${VALUE}" >>"$FILE"
    fi
}


WEBRTC_FILE="/etc/kurento/modules/kurento/WebRtcEndpoint.conf.ini"

if [[ -n "${WEBRTC_DSCP:-}" ]]; then
    set_parameter "$WEBRTC_FILE" "qos-dscp" "$WEBRTC_DSCP"
fi

sysctl -w kernel.core_pattern=/crash_dumps/core-%e.%p.%h.%t

/entrypoint.sh
