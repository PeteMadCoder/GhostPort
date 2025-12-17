#!/bin/bash
# =================================================================
# GHOSTPORT WATCHDOG (v5.0)
# Purpose: Ensures GhostPort stays alive and prevents lockout.
# =================================================================

BIN_PATH="./target/release/ghostport"
MAX_RESTARTS=3
WINDOW_SECONDS=60
LOG_FILE="./watchdog.log"
CRITICAL_ALERT_WEBHOOK="https://discord.com/api/webhooks/12345/abcde"

restart_count=0
start_time=$(date +%s)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

alert() {
    curl -H "Content-Type: application/json" \
         -d "{\"content\": \"🚨 **CRITICAL FAILURE** 🚨\nGhostPort has crashed multiple times. EMERGENCY MODE ACTIVATED. SSH (Port 22) is now OPEN.\"}" \
         "$CRITICAL_ALERT_WEBHOOK"
}



log "Starting GhostPort Watchdog..."

while true; do
    # Check restart window
    current_time=$(date +%s)
    time_diff=$((current_time - start_time))

    if [ $time_diff -gt $WINDOW_SECONDS ]; then
        # Reset counter if window passed
        restart_count=0
        start_time=$current_time
    fi

    log "Launching GhostPort..."
    
    # Run GhostPort (assuming env vars are set externally or here)
    if [ -z "$GHOSTPORT_MASTER_KEY" ]; then
        log "ERROR: GHOSTPORT_MASTER_KEY not set!"
        exit 1
    fi
    
    $BIN_PATH server
    EXIT_CODE=$?

    if [ $EXIT_CODE -ne 0 ]; then
        log "GhostPort crashed with exit code $EXIT_CODE."
        ((restart_count++))
        
        log "Restart Count: $restart_count / $MAX_RESTARTS"

        if [ $restart_count -ge $MAX_RESTARTS ]; then
            log "CRITICAL: Too many restarts. GhostPort Stopped (Fail-Closed)."
            exit 1
        fi

        sleep 2
    else
        log "GhostPort exited normally. Stopping Watchdog."
        break
    fi
done
