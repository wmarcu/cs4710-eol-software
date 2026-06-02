#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="/workspace"

# Script configuration with defaults
SCRIPT_NAME="nginx-nl"
DEFAULT_BANDWIDTH="1M" # Conservative default to avoid overwhelming networks
DEFAULT_MAX_RESULTS="0" # Default max number of successful results
DEFAULT_CONNECT_TIMEOUT="10s" # ZGrab2 connection timeout (default 10s)
DEFAULT_TARGET_TIMEOUT="10s" # ZGrab2 target timeout (default 60s)
DEFAULT_SENDERS="10" # ZGrab2 sender threads (default 1000)
DEFAULT_ALLOWLIST_FILE="$SCRIPT_DIR/nl-cidr.conf" # Default location for allowlist

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    local missing_deps=()
    local required_commands=("zmap" "zgrab2" "ztee" "jq" "python3")

    log_info "Checking prerequisites..."

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo ""
        echo "Installation instructions:"
        [[ " ${missing_deps[*]} " =~ " zmap " ]] && echo "  - ZMap: https://github.com/zmap/zmap#installing-from-source"
        [[ " ${missing_deps[*]} " =~ " zgrab2 " ]] && echo "  - ZGrab2: https://github.com/zmap/zgrab2#building-from-source"
        [[ " ${missing_deps[*]} " =~ " ztee " ]] && echo "  - ztee: comes with ZMap installation"
        [[ " ${missing_deps[*]} " =~ " jq " ]] && echo "  - jq: https://stedolan.github.io/jq/download/"
        [[ " ${missing_deps[*]} " =~ " python3 " ]] && echo "  - Python3: install with your package manager"
        return 1
    fi

    # Check if zgrab2 has http module
    if ! zgrab2 http --help &> /dev/null; then
        log_error "ZGrab2 HTTP module not available. Please ensure ZGrab2 is properly installed."
        return 1
    fi

    log_info "All prerequisites satisfied"
    return 0
}

check_allowlist_file() {
    if [ ! -f "$ALLOWLIST_FILE" ]; then
        log_error "Allowlist file not found: $ALLOWLIST_FILE"
        return 1
    fi

    local line_count=$(wc -l < "$ALLOWLIST_FILE")
    log_info "Using allowlist file: $ALLOWLIST_FILE ($line_count subnets)"
    return 0
}

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Script to scan for nginx servers in the Netherlands using ZMap and ZGrab2.

OPTIONS:
    -w, --allowlist FILE       Allowlist file with Netherlands IP ranges (default: $DEFAULT_ALLOWLIST_FILE)
    -b, --bandwidth RATE       ZMap bandwidth (default: $DEFAULT_BANDWIDTH)
    -n, --max-results NUM      Maximum number of results to return (ZMap --max-results) (default: $DEFAULT_MAX_RESULTS)
    -c, --connect-timeout TIME ZGrab2 connection timeout (default: $DEFAULT_CONNECT_TIMEOUT)
    -t, --target-timeout TIME  ZGrab2 target timeout (default: $DEFAULT_TARGET_TIMEOUT)
    -s, --senders NUM          ZGrab2 sender threads (default: $DEFAULT_SENDERS)
    -o, --output-dir DIR       Output directory (default: data/$SCRIPT_NAME/timestamp/)
    -h, --help                 Show this help message
EOF
}

parse_args() {
    BANDWIDTH="$DEFAULT_BANDWIDTH"
    MAX_RESULTS="$DEFAULT_MAX_RESULTS"
    CONNECT_TIMEOUT="$DEFAULT_CONNECT_TIMEOUT"
    TARGET_TIMEOUT="$DEFAULT_TARGET_TIMEOUT"
    SENDERS="$DEFAULT_SENDERS"
    ALLOWLIST_FILE="$DEFAULT_ALLOWLIST_FILE"
    CUSTOM_OUTPUT_DIR=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            -w|--allowlist)
                ALLOWLIST_FILE="$2"
                shift 2
                ;;
            -b|--bandwidth)
                BANDWIDTH="$2"
                shift 2
                ;;
            -n|--max-results)
                MAX_RESULTS="$2"
                shift 2
                ;;
            -c|--connect-timeout)
                CONNECT_TIMEOUT="$2"
                shift 2
                ;;
            -t|--target-timeout)
                TARGET_TIMEOUT="$2"
                shift 2
                ;;
            -s|--senders)
                SENDERS="$2"
                shift 2
                ;;
            -o|--output-dir)
                CUSTOM_OUTPUT_DIR="$2"
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
    log_info "Output directory: $OUTPUT_BASE_DIR"
}

add_cve_mapping() {
    local input_file="$1"
    local output_file="$2"
    local enricher_script="$PROJECT_ROOT/data/processing/enrich_nginx_versions.py"

    if [ ! -f "$enricher_script" ]; then
        log_error "CVE enrichment script not found: $enricher_script"
        return 1
    fi

    python3 "$enricher_script" "$input_file" "$output_file"
}

run_scan() {
    local results_file="$OUTPUT_BASE_DIR/nginx_versions.csv"
    local metadata_file="$OUTPUT_BASE_DIR/metadata.txt"
    local subnet_count=$(wc -l < "$ALLOWLIST_FILE")
    local start_time=$(date +"%Y-%m-%d %H:%M:%S")
    local start_epoch=$(date +%s)

    echo "ip,status_code,server_header,nginx_version" > "$results_file"

    log_info "Starting scan for nginx servers in Netherlands..."
    log_info "Configuration:"
    echo "  - Allowlist: $ALLOWLIST_FILE"
    echo "  - Bandwidth: $BANDWIDTH"
    echo "  - Max results: $MAX_RESULTS"
    echo "  - Connect timeout: $CONNECT_TIMEOUT"
    echo "  - Target timeout: $TARGET_TIMEOUT"
    echo "  - Senders: $SENDERS"

    # Run the main pipeline
    # ZMap scans allowlist -> ztee buffers -> ZGrab2 does HTTP grab -> jq filters -> save results
    log_info "Running scan pipeline (this may take a while)..."

    zmap -p 80 \
        --bandwidth="$BANDWIDTH" \
        --max-results="$MAX_RESULTS" \
        --allowlist-file="$ALLOWLIST_FILE" \
        --output-module=csv \
        --output-fields=saddr \
        --output-filter="success = 1 && repeat = 0" \
        --no-header-row | \
        ztee --raw /dev/null | \
        zgrab2 http \
            --senders="$SENDERS" \
            --connect-timeout="$CONNECT_TIMEOUT" \
            --target-timeout="$TARGET_TIMEOUT" \
            --port=80 \
            --max-redirects=2 \
            --max-size=512 | \
        jq -r --unbuffered '
    select(.data.http.status == "success") |
    . as $root |
    ($root.data.http.result.response.headers.server // [null]) as $server_array |
    ($server_array | map(select(. != null)) | join("; ")) as $server_string |
    select($server_string != "" and ($server_string | test("nginx"; "i"))) |
    [
        $root.ip,
        ($root.data.http.result.response.status_line | split(" ") | .[0] // "unknown"),
        $server_string,
        ($server_string | capture("nginx/(?<version>[0-9.]+)"; "i") // {version: "unknown"} | .version)
    ] |
    @csv
' >> "$results_file"
    local cve_results_file="$OUTPUT_BASE_DIR/nginx_versions_cves.csv"
    add_cve_mapping "$results_file" "$cve_results_file"
    log_info "CVE-enriched results saved in $cve_results_file"

    local end_time=$(date +"%Y-%m-%d %H:%M:%S")
    local end_epoch=$(date +%s)
    local duration=$((end_epoch - start_epoch))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))

    local nginx_responses=0
    local nginx_with_version=0
    local nginx_without_version=0

    if [ -f "$results_file" ]; then
        nginx_responses=$(tail -n +2 "$results_file" 2>/dev/null | wc -l || echo "0")
        nginx_responses=${nginx_responses:-0}

        if [ "$nginx_responses" -gt 0 ]; then
            nginx_with_version=$(tail -n +2 "$results_file" 2>/dev/null | cut -d',' -f4 | sed 's/"//g' | grep -v "unknown" | grep -v "^$" | wc -l || echo "0")
            nginx_with_version=${nginx_with_version:-0}
            nginx_without_version=$((nginx_responses - nginx_with_version))
        fi
    fi

    local eol_servers=0
    local supported_servers=0
    local hidden_servers=0
    local vulnerable_servers=0

    if [ -f "$cve_results_file" ]; then
        eol_servers=$(awk -F',' 'NR>1 && $5=="yes"{count++} END{print count+0}' "$cve_results_file")
        supported_servers=$(awk -F',' 'NR>1 && $5=="no"{count++} END{print count+0}' "$cve_results_file")
        hidden_servers=$(awk -F',' 'NR>1 && $5=="unknown"{count++} END{print count+0}' "$cve_results_file")
        vulnerable_servers=$(awk -F',' 'NR>1 && $6!="version hidden" && $6!="current stable branch" && $6!="current mainline branch" && $6!="no local mapping"{count++} END{print count+0}' "$cve_results_file")
    fi

    cat > "$metadata_file" << EOF
Scan Metadata
=============
Scan started: $start_time
Scan ended: $end_time
Scan duration: $duration_formatted ($duration seconds)
Script version: $SCRIPT_NAME

Configuration Parameters:
------------------------
Allowlist file: $ALLOWLIST_FILE ($subnet_count subnets)
Bandwidth: $BANDWIDTH
Max results requested: $MAX_RESULTS
ZGrab2 connect timeout: $CONNECT_TIMEOUT
ZGrab2 target timeout: $TARGET_TIMEOUT
ZGrab2 senders: $SENDERS

Results Summary:
---------------
Nginx servers found: $nginx_responses
  - Nginx with version number: $nginx_with_version
  - Nginx without version: $((nginx_responses - nginx_with_version))

CVE Summary:
-----------
Servers on EOL nginx versions: $eol_servers
Servers on supported branches: $supported_servers
Servers with hidden version: $hidden_servers
Servers with known vulnerabilities: $vulnerable_servers
EOF

    if [ "$nginx_responses" -eq 0 ]; then
        log_warn "No successful HTTP responses for nginx servers received"
        return 0
    fi
}

main() {
    parse_args "$@"

    log_info "Starting $SCRIPT_NAME scan script"

    if ! check_prerequisites; then
        exit 1
    fi

    if ! check_allowlist_file; then
        exit 1
    fi

    setup_output_directory
    run_scan

    log_info "Done! Check $OUTPUT_BASE_DIR for results"
}

# Run main function with all arguments
main "$@"