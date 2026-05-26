#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="/workspace"

# Script configuration with defaults
SCRIPT_NAME="grab-banners"
DEFAULT_SENDERS=100
DEFAULT_TIMEOUT="10s"
DEFAULT_CONFIG_FILE="$SCRIPT_DIR/multiple.ini"
DEFAULT_TARGET_IPS="$SCRIPT_DIR/found-ips.txt"

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

check_targets_file() {
    if [ ! -f "$TARGET_IPS" ]; then
        log_error "Allowlist file not found: $TARGET_IPS"
        return 1
    fi

    local line_count=$(wc -l < "$TARGET_IPS")
    log_info "Targeting IPs in file: $TARGET_IPS ($line_count total)"
    return 0
}

show_help() {
    cat << EOF
Usage: $0 -i TARGET_IPS -o OUTPUT_DIR [OPTIONS]

Simple script to grab banners from a list of IPs using zgrab2 and output CSV.

OPTIONS:
    -i, --input-file FILE     File with list of IPs (one per line)
    -o, --output-dir DIR      Output directory
    -s, --senders NUM         Number of zgrab2 sender threads (default: $DEFAULT_SENDERS)
    -t, --timeout TIME        Connection timeout (default: $DEFAULT_TIMEOUT)
    -h, --help                Show this help message
EOF
}

parse_args() {
    TARGET_IPS="$DEFAULT_TARGET_IPS"
    CUSTOM_OUTPUT_DIR=""
    SENDERS="$DEFAULT_SENDERS"
    TIMEOUT="$DEFAULT_TIMEOUT"

    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--input-file)
                TARGET_IPS="$2"
                shift 2
                ;;
            -o|--output-dir)
                CUSTOM_OUTPUT_DIR="$2"
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
}

setup_output_directory() {
    if [ -n "$CUSTOM_OUTPUT_DIR" ]; then
        OUTPUT_BASE_DIR="$CUSTOM_OUTPUT_DIR"
    else
        local timestamp=$(date +%Y-%m-%d_%H-%M-%S)
        OUTPUT_BASE_DIR="$PROJECT_ROOT/data/$SCRIPT_NAME/$timestamp"
    fi

    mkdir -p "$OUTPUT_BASE_DIR"
    OUTPUT_FILE="$OUTPUT_BASE_DIR/grab-results.csv"
    METADATA_FILE="$OUTPUT_BASE_DIR/metadata.txt"

    log_info "Output directory: $OUTPUT_BASE_DIR"
}

run_scan() {
    log_info "Starting banner grab..."
    log_info "Target IPs: $TARGET_IPS"
    log_info "Senders: $SENDERS"
    log_info "Timeout: $TIMEOUT"

    local start_time=$(date +"%Y-%m-%d %H:%M:%S")
    local start_epoch=$(date +%s)

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

    local end_time=$(date +"%Y-%m-%d %H:%M:%S")
    local end_epoch=$(date +%s)
    local duration=$((end_epoch - start_epoch))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))

    local total_targets=0
    local total_results=0
    local nginx_with_version=0
    local nginx_without_version=0

    total_targets=$(wc -l < "$TARGET_IPS")

    if [ -f "$OUTPUT_FILE" ]; then
        total_results=$(tail -n +2 "$OUTPUT_FILE" | wc -l)

        nginx_with_version=$(tail -n +2 "$OUTPUT_FILE" \
            | cut -d',' -f5 \
            | sed 's/"//g' \
            | grep -v "^unknown$" \
            | grep -v "^$" \
            | wc -l)

        nginx_without_version=$((total_results - nginx_with_version))
    fi

    cat > "$METADATA_FILE" << EOF
Grab Metadata
=============
Grab started: $start_time
Grab ended: $end_time
Grab duration: $duration_formatted ($duration seconds)
Grab version: $SCRIPT_NAME

Configuration Parameters:
------------------------
Input targets file: $TARGET_IPS
Total targets provided: $total_targets
Senders: $SENDERS
Timeout: $TIMEOUT
ZGrab2 config file: $DEFAULT_CONFIG_FILE

Results Summary:
---------------
Total nginx results: $total_results
  - With version number: $nginx_with_version
  - Without version number: $nginx_without_version
EOF
}

main() {
    parse_args "$@"

    if ! check_prerequisites; then
        exit 1
    fi

    if ! check_targets_file; then
        exit 1
    fi

    setup_output_directory
    run_scan

    log_info "Done! Check $OUTPUT_BASE_DIR for results"
}

main "$@"