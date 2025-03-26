#!/bin/bash

# Bash options for strict error checking
set -o errexit -o errtrace -o pipefail -o nounset

# Trace all commands
set -o xtrace

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
SIPRTP_FILE="/etc/kurento/modules/siprtp/SipRtpEndpoint.conf.ini"

if [[ -n "${WEBRTC_DSCP:-}" ]]; then
    set_parameter "$WEBRTC_FILE" "qos-dscp" "$WEBRTC_DSCP"
fi

if [[ -n "${SIPRTP_DSCP:-}" ]]; then
    set_parameter "$SIPRTP_FILE" "qos-dscp" "$SIPRTP_DSCP"
fi

if [[ -n "${SIPRTP_AUDIO_CODECS:-}" ]]; then
    set_parameter "$SIPRTP_FILE" "audioCodecs" "$SIPRTP_AUDIO_CODECS"
fi

if [[ -n "${SIPRTP_VIDEO_CODECS:-}" ]]; then
    set_parameter "$SIPRTP_FILE" "videoCodecs" "$SIPRTP_VIDEO_CODECS"
fi

# SipRtpEndpoint public IP settings
if [[ -n "${SIPRTP_EXTERNAL_IPV4:-}" ]]; then
    if [[ "$SIPRTP_EXTERNAL_IPV4" == "auto" ]]; then
        if IP="$(/getmyip.sh --ipv4)"; then
            set_parameter "$SIPRTP_FILE" "externalIPv4" "$IP"
        fi
    else
        set_parameter "$SIPRTP_FILE" "externalIPv4" "$SIPRTP_EXTERNAL_IPV4"
    fi
fi
if [[ -n "${SIPRTP_EXTERNAL_IPV6:-}" ]]; then
    if [[ "$SIPRTP_EXTERNAL_IPV6" == "auto" ]]; then
        if IP="$(/getmyip.sh --ipv6)"; then
            set_parameter "$SIPRTP_FILE" "externalIPv6" "$IP"
        fi
    else
        set_parameter "$SIPRTP_FILE" "externalIPv6" "$SIPRTP_EXTERNAL_IPV6"
    fi
fi

sysctl -w kernel.core_pattern=/crash_dumps/core.%p

/entrypoint.sh

