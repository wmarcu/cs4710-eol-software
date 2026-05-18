#!/usr/bin/env bash

set -euo pipefail

# Script configuration with defaults
SCRIPT_NAME="grab-banners"
DEFAULT_SENDERS=100
DEFAULT_TIMEOUT="10s"
DEFAULT_CONFIG_FILE="multiple.ini"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    local missing_deps=()
    local required_commands=("zgrab2" "jq")

    log_info "Checking prerequisites..."

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install them before running this script."
        return 1
    fi

    log_info "All prerequisites satisfied"
    return 0
}

show_help() {
    cat << EOF
Usage: $0 -i TARGET_IPS -o OUTPUT_FILE [OPTIONS]

Simple script to grab banners from a list of IPs using zgrab2 and output CSV.

OPTIONS:
    -i, --input-file FILE     File with list of IPs (one per line)
    -o, --output-file FILE    CSV file to save results
    -s, --senders NUM         Number of zgrab2 sender threads (default: $DEFAULT_SENDERS)
    -t, --timeout TIME        Connection timeout (default: $DEFAULT_TIMEOUT)
    -h, --help                Show this help message
EOF
}

parse_args() {
    TARGET_IPS="found-ips.txt"
    OUTPUT_FILE="grab-results.csv"
    SENDERS="$DEFAULT_SENDERS"
    TIMEOUT="$DEFAULT_TIMEOUT"

    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--input-file)
                TARGET_IPS="$2"
                shift 2
                ;;
            -o|--output-file)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -s|--senders)
                SENDERS="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [ -z "$TARGET_IPS" ] || [ -z "$OUTPUT_FILE" ]; then
        log_error "Input file and output file are required"
        show_help
        exit 1
    fi
}

run_scan() {
    log_info "Starting banner grab..."
    log_info "Target IPs: $TARGET_IPS"
    log_info "Output file: $OUTPUT_FILE"
    log_info "Senders: $SENDERS"
    log_info "Timeout: $TIMEOUT"

    # Temporary file for raw zgrab2 output
    local tmp_json
    tmp_json=$(mktemp)

    zgrab2 multiple \
        --input-file="$TARGET_IPS" \
        --senders="$SENDERS" \
        --config-file="$DEFAULT_CONFIG_FILE" \
        --output-file="$tmp_json"

    log_info "Processing results with jq..."

    # Convert to CSV with IP, HTTP status, Server header, and nginx version if present
    {
        echo "ip,port,status_code,server_header,nginx_version"
        jq -r --unbuffered '  
    . as $root |
        (
        if .data.http80 then
            {port: "80", data: .data.http80}
        else
            empty
        end
    ),
    (
        if .data.http443 then
            {port: "443", data: .data.http443}
        else
            empty
        end
    ) |
    select(.data.status == "success") |
    (.data.result.response.headers.server // [null]) as $server_array |
    ($server_array | map(select(. != null)) | join("; ")) as $server_string |
    select($server_string != "" and ($server_string | test("nginx"; "i"))) |
    [
        $root.ip,
        .port,
        (.data.result.response.status_line | split(" ") | .[0] // "unknown"),
        $server_string,
        ($server_string | capture("nginx/(?<version>[0-9.]+)"; "i") // {version: "unknown"} | .version)
    ] |
    @csv
' "$tmp_json"
    } > "$OUTPUT_FILE"

    rm -f "$tmp_json"
    log_info "Grab completed! CSV results saved in $OUTPUT_FILE"
}

main() {
    parse_args "$@"

    if ! check_prerequisites; then
        exit 1
    fi

    run_scan
}

main "$@"