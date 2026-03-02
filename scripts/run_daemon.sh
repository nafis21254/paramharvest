#!/usr/bin/env bash
#
# ParamHarvest - Daemon/Background Service Script
# Run ParamHarvest in the background as a service
#
# Usage: ./run_daemon.sh [start|stop|status|restart]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="${PROJECT_DIR}/logs/paramharvest.pid"
LOG_FILE="${PROJECT_DIR}/logs/daemon.log"

# Default configuration
PROXY_PORT="${PARAMHARVEST_PORT:-8080}"
DOMAIN_FILTER="${PARAMHARVEST_DOMAIN:-}"
OUTPUT_DIR="${PARAMHARVEST_OUTPUT:-${PROJECT_DIR}/logs}"
REFLECTION="${PARAMHARVEST_REFLECTION:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }

# Ensure directories exist
mkdir -p "${OUTPUT_DIR}"
mkdir -p "$(dirname "$PID_FILE")"

get_pid() {
    if [ -f "$PID_FILE" ]; then
        cat "$PID_FILE"
    else
        echo ""
    fi
}

is_running() {
    PID=$(get_pid)
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

build_command() {
    CMD="mitmdump --listen-port ${PROXY_PORT} -s ${PROJECT_DIR}/paramharvest.py"
    
    # Add domain filter if specified
    if [ -n "$DOMAIN_FILTER" ]; then
        CMD="${CMD} --set domain=${DOMAIN_FILTER}"
    fi
    
    # Add output directory
    CMD="${CMD} --set output=${OUTPUT_DIR}"
    
    # Add reflection flag
    if [ "$REFLECTION" = "true" ]; then
        CMD="${CMD} --set reflection=true"
    fi
    
    # Quiet mode for daemon
    CMD="${CMD} --set quiet=true"
    
    echo "$CMD"
}

start_daemon() {
    if is_running; then
        print_warning "ParamHarvest is already running (PID: $(get_pid))"
        return 1
    fi
    
    print_status "Starting ParamHarvest daemon..."
    print_status "Port: ${PROXY_PORT}"
    print_status "Domain Filter: ${DOMAIN_FILTER:-ALL}"
    print_status "Output Dir: ${OUTPUT_DIR}"
    print_status "Reflection Check: ${REFLECTION}"
    
    # Build and run command
    CMD=$(build_command)
    
    # Start in background
    nohup $CMD > "$LOG_FILE" 2>&1 &
    PID=$!
    
    # Save PID
    echo $PID > "$PID_FILE"
    
    # Wait a moment and verify
    sleep 2
    
    if is_running; then
        print_status "ParamHarvest started successfully (PID: $PID)"
        print_status "Log file: ${LOG_FILE}"
        print_status "Configure browser proxy to: 127.0.0.1:${PROXY_PORT}"
    else
        print_error "Failed to start ParamHarvest"
        print_error "Check log file: ${LOG_FILE}"
        rm -f "$PID_FILE"
        return 1
    fi
}

stop_daemon() {
    if ! is_running; then
        print_warning "ParamHarvest is not running"
        rm -f "$PID_FILE"
        return 0
    fi
    
    PID=$(get_pid)
    print_status "Stopping ParamHarvest (PID: $PID)..."
    
    # Send SIGTERM for graceful shutdown
    kill -TERM "$PID" 2>/dev/null
    
    # Wait for process to stop
    for i in {1..10}; do
        if ! is_running; then
            print_status "ParamHarvest stopped"
            rm -f "$PID_FILE"
            return 0
        fi
        sleep 1
    done
    
    # Force kill if still running
    print_warning "Process didn't stop gracefully, forcing..."
    kill -9 "$PID" 2>/dev/null
    rm -f "$PID_FILE"
    
    print_status "ParamHarvest stopped"
}

show_status() {
    if is_running; then
        PID=$(get_pid)
        print_status "ParamHarvest is running (PID: $PID)"
        
        # Show process info
        echo ""
        echo -e "${CYAN}Process Info:${NC}"
        ps -p "$PID" -o pid,user,%cpu,%mem,start,command 2>/dev/null || true
        
        # Show recent log entries
        echo ""
        echo -e "${CYAN}Recent Log (last 10 lines):${NC}"
        tail -n 10 "$LOG_FILE" 2>/dev/null || echo "No log file found"
        
        # Show stats if available
        STATS_FILE="${OUTPUT_DIR}/raw_params.json"
        if [ -f "$STATS_FILE" ]; then
            echo ""
            echo -e "${CYAN}Current Statistics:${NC}"
            python3 -c "
import json
with open('${STATS_FILE}') as f:
    data = json.load(f)
    meta = data.get('metadata', {})
    stats = meta.get('statistics', {})
    print(f\"  Total Parameters: {meta.get('total_unique_params', 0)}\")
    print(f\"  Unique Keys: {meta.get('total_unique_keys', 0)}\")
    print(f\"  By Source: QUERY={stats.get('QUERY',0)} FORM={stats.get('FORM',0)} JSON={stats.get('JSON',0)}\")
" 2>/dev/null || true
        fi
    else
        print_warning "ParamHarvest is not running"
        
        # Check if PID file exists but process is dead
        if [ -f "$PID_FILE" ]; then
            print_warning "Stale PID file found, removing..."
            rm -f "$PID_FILE"
        fi
    fi
}

restart_daemon() {
    print_status "Restarting ParamHarvest..."
    stop_daemon
    sleep 2
    start_daemon
}

show_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        print_error "Log file not found: ${LOG_FILE}"
    fi
}

print_usage() {
    echo -e "${CYAN}ParamHarvest Daemon Controller${NC}"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start     Start ParamHarvest in background"
    echo "  stop      Stop ParamHarvest daemon"
    echo "  restart   Restart ParamHarvest daemon"
    echo "  status    Show daemon status and statistics"
    echo "  logs      Follow daemon log output"
    echo ""
    echo "Environment Variables:"
    echo "  PARAMHARVEST_PORT       Proxy port (default: 8080)"
    echo "  PARAMHARVEST_DOMAIN     Domain filter (default: all)"
    echo "  PARAMHARVEST_OUTPUT     Output directory (default: ./logs)"
    echo "  PARAMHARVEST_REFLECTION Enable reflection check (default: false)"
    echo ""
    echo "Examples:"
    echo "  $0 start"
    echo "  PARAMHARVEST_DOMAIN=target.com $0 start"
    echo "  PARAMHARVEST_PORT=9090 PARAMHARVEST_REFLECTION=true $0 start"
}

# Main
case "${1:-}" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        restart_daemon
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    -h|--help|help)
        print_usage
        ;;
    *)
        print_usage
        exit 1
        ;;
esac
