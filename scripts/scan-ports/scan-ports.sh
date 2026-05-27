#!/usr/bin/env bash  
  
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="/workspace"
  
# Script configuration with defaults
SCRIPT_NAME="scan-ports"
DEFAULT_BANDWIDTH="1M"
DEFAULT_MAX_RESULTS="0"
DEFAULT_PORTS="80" # Ports to scan, separated by commas
DEFAULT_ALLOWLIST_FILE="$SCRIPT_DIR/nl-cidr.conf"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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
    local required_commands=("zmap")

    log_info "Checking prerequisites..."

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Installation instructions:"
        [[ " ${missing_deps[*]} " =~ " zmap " ]] && echo "  - ZMap: https://github.com/zmap/zmap#installing-from-source"
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

Script to scan for responsive hosts using ZMap and output in zgrab-compatible format.

OPTIONS:
    -w, --allowlist FILE       Allowlist file with IP ranges (default: $DEFAULT_ALLOWLIST_FILE)
    -p, --ports PORTS          Comma-separated list of ports to scan (default: $DEFAULT_PORTS)
    -b, --bandwidth RATE       ZMap bandwidth (default: $DEFAULT_BANDWIDTH)
    -n, --max-results NUM      Maximum number of results to return (default: $DEFAULT_MAX_RESULTS)
    -o, --output-dir DIR       Output directory (default: data/$SCRIPT_NAME/timestamp/)
    -h, --help                 Show this help message
  
OUTPUT FORMAT:
    Outputs in zgrab-compatible format: IP,,,PORT
    Each line contains: IP address, empty domain, empty tag, responding port
EOF
}
  
parse_args() {
    BANDWIDTH="$DEFAULT_BANDWIDTH"
    MAX_RESULTS="$DEFAULT_MAX_RESULTS"
    PORTS="$DEFAULT_PORTS"
    ALLOWLIST_FILE="$DEFAULT_ALLOWLIST_FILE"
    CUSTOM_OUTPUT_DIR=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            -w|--allowlist)
                ALLOWLIST_FILE="$2"
                shift 2
                ;;
            -p|--ports)
                PORTS="$2"
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

run_scan() {
    local results_file="$OUTPUT_BASE_DIR/responsive_hosts.csv"
    local metadata_file="$OUTPUT_BASE_DIR/metadata.txt"
    local subnet_count=$(wc -l < "$ALLOWLIST_FILE")
    local start_time=$(date +"%Y-%m-%d %H:%M:%S")
    local start_epoch=$(date +%s)

    log_info "Starting scan for responsive hosts..."
    log_info "Configuration:"
    echo "  - Allowlist: $ALLOWLIST_FILE"
    echo "  - Ports: $PORTS"
    echo "  - Bandwidth: $BANDWIDTH"
    echo "  - Max results: $MAX_RESULTS"
  
    # Run ZMap with multi-port support
    # Output format: saddr (IP), sport (port) -> formatted as IP,,,PORT for zgrab
    log_info "Running ZMap scan (this may take a while)..."

    zmap -p "$PORTS" \
        --bandwidth="$BANDWIDTH" \
        --max-results="$MAX_RESULTS" \
        --allowlist-file="$ALLOWLIST_FILE" \
        --output-module=csv \
        --output-fields=saddr,sport \
        --output-filter="success = 1 && repeat = 0" \
        --no-header-row \
        --dedup-method=window \
        --dedup-window-size=1000000 | \
        awk -F',' '{print $1 ",,," $2}' > "$results_file"

    local end_time=$(date +"%Y-%m-%d %H:%M:%S")
    local end_epoch=$(date +%s)
    local duration=$((end_epoch - start_epoch))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))

    local total_results=0
    if [ -f "$results_file" ]; then
        total_results=$(wc -l < "$results_file" 2>/dev/null || echo "0")
        total_results=${total_results:-0}
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
Port numbers scanned: $PORTS
Bandwidth: $BANDWIDTH
Max results requested: $MAX_RESULTS

Results Summary:
---------------
Total responsive (IP,port) pairs: $total_results
EOF

    if [ "$total_results" -eq 0 ]; then
        log_warn "No successful responses received"
        return 0
    fi

    log_info "Scan complete! Found $total_results responsive (IP,port) pairs"
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

main "$@"