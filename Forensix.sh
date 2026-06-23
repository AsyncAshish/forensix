#!/bin/bash

#COLORS

RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
CYAN='\e[0;36m'
BLUE='\e[0;34m'
MAGENTA='\e[0;35m'
BOLD='\e[1m'
RESET='\e[0m'

# GLOBAL VARIABLES
START_DATE=""
END_DATE=""
START_TIME=""
END_TIME=""
START_EPOCH=0
END_EPOCH=0
REPORT_FILE=""
FINDINGS=0   

# =============================================================================
# REPEATED UTILITY HELPERS
# =============================================================================

# Check if a command exists on this system
cmd_exists() {
    command -v "$1" &>/dev/null
}

# Convert a date+time string to Unix epoch
to_epoch() {
    date -d "$1 $2" +%s 2>/dev/null
}

# Check if a given timestamp falls within our target range
in_range() {
    local ts="$1"
    local ts_epoch
    ts_epoch=$(date -d "$ts" +%s 2>/dev/null)

    if [ -z "$ts_epoch" ]; then
        return 1
    fi

    if [ "$ts_epoch" -ge "$START_EPOCH" ] && [ "$ts_epoch" -le "$END_EPOCH" ]; then
        return 0
    else
        return 1
    fi
}

# PRINT HEADER 
print_section() {
    local title="$1"
    echo ""
    echo -e "${BLUE}${BOLD}┌─────────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}${BOLD}│  $title${RESET}"
    echo -e "${BLUE}${BOLD}└─────────────────────────────────────────────┘${RESET}"
    echo "" >> "$REPORT_FILE"
    echo "================================================" >> "$REPORT_FILE"
    echo "  $title" >> "$REPORT_FILE"
    echo "================================================" >> "$REPORT_FILE"
}

# Log to both screen and file
log_event() {
    local color="$1"
    local tag="$2"
    local message="$3"
    echo -e "  ${color}${tag}${RESET} $message"
    echo "  [$tag] $message" >> "$REPORT_FILE"
    FINDINGS=$((FINDINGS + 1))
}

log_info() {
    echo -e "  ${CYAN}$1${RESET}"
    echo "  $1" >> "$REPORT_FILE"
}

log_none() {
    echo -e "  ${YELLOW}No activity found in this time range.${RESET}"
    echo "  [--] No activity found in this time range." >> "$REPORT_FILE"
}

# Many log files use format: "Jun 20 14:30:01" or "2026-06-20T14:30:01"
# This function filters a log file to only lines in our time range
grep_by_time() {
    local logfile="$1"
    [ ! -f "$logfile" ] && return

    awk -v start="$START_EPOCH" -v end="$END_EPOCH" '
    {
        # Try to parse date from common log formats
        cmd = "date -d \""$1" "$2" "$3"\" +%s 2>/dev/null"
        cmd | getline ts
        close(cmd)
        if (ts >= start && ts <= end) print $0
    }' "$logfile" 2>/dev/null
}


# =============================================================================
# MAIN PROCEDURAL EXECUTION SEQUENCE
# =============================================================================

# PRINT BANNER
clear
echo -e "${CYAN}"
echo "  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗"
echo "  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝"
echo "  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     "
echo "  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     "
echo "  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗"
echo "  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝"
echo -e "${RESET}"
echo -e "  ${BOLD}ForensicTrace — Linux Activity Timeline Analyzer${RESET}"
echo -e "  ${YELLOW}Read-only forensic tool | kernyxlabs.in${RESET}"
echo ""

# Check if running as root (needed for some log files)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Not running as root. Some logs may be inaccessible.${RESET}"
    echo -e "${YELLOW}    Run with: sudo ./forensic_trace.sh for full access${RESET}"
    echo ""
fi


# DETECTING LINUX DISTRO
echo -e "${CYAN}[*] Detecting system...${RESET}"
if [ -f /etc/os-release ]; then
    DISTRO=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
elif [ -f /etc/redhat-release ]; then
    DISTRO="rhel"
elif [ -f /etc/arch-release ]; then
    DISTRO="arch"
else
    DISTRO="unknown"
fi

# Set log paths based on distro family
if [[ "$DISTRO" =~ ^(ubuntu|debian|kali|parrot|mint|pop)$ ]]; then
    AUTH_LOG="/var/log/auth.log"
    SYSLOG="/var/log/syslog"
    DPKG_LOG="/var/log/dpkg.log"
    DISTRO_FAMILY="debian"
elif [[ "$DISTRO" =~ ^(fedora|centos|rhel|rocky|alma)$ ]]; then
    AUTH_LOG="/var/log/secure"
    SYSLOG="/var/log/messages"
    DPKG_LOG="/var/log/yum.log"   # or dnf.log
    DISTRO_FAMILY="redhat"
elif [[ "$DISTRO" =~ ^(arch|manjaro|endeavouros)$ ]]; then
    AUTH_LOG=""   # Arch uses journalctl only
    SYSLOG=""
    DPKG_LOG=""
    DISTRO_FAMILY="arch"
else
    AUTH_LOG="/var/log/auth.log"
    SYSLOG="/var/log/syslog"
    DPKG_LOG=""
    DISTRO_FAMILY="unknown"
fi

if cmd_exists journalctl; then
    HAS_JOURNALD=true
else
    HAS_JOURNALD=false
fi

echo -e "  ${GREEN}[✓]${RESET} Detected: ${BOLD}$DISTRO${RESET} (family: $DISTRO_FAMILY)"
echo -e "  ${GREEN}[✓]${RESET} Journald: $HAS_JOURNALD"


# GET TIME RANGE
echo ""
echo -e "${BOLD}Set your investigation time range:${RESET}"
echo -e "${YELLOW}(Press Enter to use default: last 24 hours)${RESET}"
echo ""

# Get current date and time for defaults
NOW_DATE=$(date +"%Y-%m-%d")
YESTERDAY_DATE=$(date -d "yesterday" +"%Y-%m-%d")
NOW_TIME=$(date +"%H:%M:%S")

# --- Start Date ---
echo -e "${CYAN}Start date (YYYY-MM-DD) [default: $YESTERDAY_DATE]:${RESET}"
read -p "> " INPUT_START_DATE
START_DATE="${INPUT_START_DATE:-$YESTERDAY_DATE}"

# --- Start Time ---
echo -e "${CYAN}Start time (HH:MM:SS) [default: 00:00:00]:${RESET}"
read -p "> " INPUT_START_TIME
START_TIME="${INPUT_START_TIME:-00:00:00}"

# --- End Date ---
echo -e "${CYAN}End date (YYYY-MM-DD) [default: $NOW_DATE]:${RESET}"
read -p "> " INPUT_END_DATE
END_DATE="${INPUT_END_DATE:-$NOW_DATE}"

# --- End Time ---
echo -e "${CYAN}End time (HH:MM:SS) [default: $NOW_TIME]:${RESET}"
read -p "> " INPUT_END_TIME
END_TIME="${INPUT_END_TIME:-$NOW_TIME}"

# Convert to epoch for easy comparison
START_EPOCH=$(to_epoch "$START_DATE" "$START_TIME")
END_EPOCH=$(to_epoch "$END_DATE" "$END_TIME")

# Validate — end must be after start
if [ -z "$START_EPOCH" ] || [ -z "$END_EPOCH" ]; then
    echo -e "${RED}[ERROR] Invalid date format. Use YYYY-MM-DD and HH:MM:SS${RESET}"
    exit 1
fi

if [ "$END_EPOCH" -le "$START_EPOCH" ]; then
    echo -e "${RED}[ERROR] End time must be after start time.${RESET}"
    exit 1
fi

# Calculate duration in human readable form
DURATION_SECS=$((END_EPOCH - START_EPOCH))
DURATION_HOURS=$((DURATION_SECS / 3600))
DURATION_MINS=$(( (DURATION_SECS % 3600) / 60 ))

echo ""
echo -e "${GREEN}[✓] Time range set:${RESET}"
echo -e "    From : ${BOLD}$START_DATE $START_TIME${RESET}"
echo -e "    To   : ${BOLD}$END_DATE $END_TIME${RESET}"
echo -e "    Span : ${BOLD}${DURATION_HOURS}h ${DURATION_MINS}m${RESET}"


# SETUP REPORT FILE
mkdir -p forensic_reports
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="forensic_reports/timeline_${START_DATE}_to_${END_DATE}_${TIMESTAMP}.txt"

{
    echo "========================================================"
    echo "  ForensicTrace — Linux Activity Timeline Report"
    echo "  Generated : $(date)"
    echo "  Hostname  : $(hostname)"
    echo "  Kernel    : $(uname -r)"
    echo "  Distro    : $DISTRO"
    echo "  From      : $START_DATE $START_TIME"
    echo "  To        : $END_DATE $END_TIME"
    echo "  Run by    : $(whoami)"
    echo "========================================================"
} > "$REPORT_FILE"

echo -e "${GREEN}[✓] Report will be saved to: ${BOLD}$REPORT_FILE${RESET}"

echo ""
echo -e "${CYAN}[*] Starting forensic collection...${RESET}"
echo ""

sleep 3
clear


# USER LOGIN / LOGOUT HISTORY
print_section "User Login / Logout History"
found_logins=0

if ! cmd_exists last; then
    log_info "  'last' command not available on this system"
else
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == *"wtmp begins"* ]] && continue
        [[ "$line" == *"reboot"* ]] && continue

        line_date=$(echo "$line" | awk '{print $5, $6, $7, $8}')
        line_epoch=$(date -d "$line_date" +%s 2>/dev/null)

        if [ -n "$line_epoch" ] && \
           [ "$line_epoch" -ge "$START_EPOCH" ] && \
           [ "$line_epoch" -le "$END_EPOCH" ]; then
            log_event "$GREEN" "LOGIN" "$line"
            found_logins=$((found_logins + 1))
        fi
    done < <(last -F 2>/dev/null)

    [ "$found_logins" -eq 0 ] && log_none
fi


# SUDO & PRIVILEGE ESCALATION
print_section "Sudo & Privilege Escalation Events"
found_sudo=0

if [ "$HAS_JOURNALD" = true ]; then
    while IFS= read -r line; do
        log_event "$YELLOW" "SUDO" "$line"
        found_sudo=$((found_sudo + 1))
    done < <(journalctl \
        --since="$START_DATE $START_TIME" \
        --until="$END_DATE $END_TIME" \
        --no-pager -q \
        SYSLOG_IDENTIFIER=sudo 2>/dev/null)
fi

if [ "$found_sudo" -eq 0 ] && [ -f "$AUTH_LOG" ]; then
    while IFS= read -r line; do
        if echo "$line" | grep -q "sudo\|COMMAND\|session opened for.*root"; then
            log_event "$YELLOW" "SUDO" "$line"
            found_sudo=$((found_sudo + 1))
        fi
    done < <(grep_by_time "$AUTH_LOG")
fi

[ "$found_sudo" -eq 0 ] && log_none


# SSH LOGIN ATTEMPTS
print_section "SSH Login Attempts (Success + Failure)"
found_ssh=0
success_ssh=0
failed_ssh=0

if [ "$HAS_JOURNALD" = true ]; then
    while IFS= read -r line; do
        if echo "$line" | grep -q "Accepted"; then
            log_event "$GREEN" "SSH-OK " "$line"
            success_ssh=$((success_ssh + 1))
        elif echo "$line" | grep -q "Failed\|Invalid\|error"; then
            log_event "$RED" "SSH-FAIL" "$line"
            failed_ssh=$((failed_ssh + 1))
        fi
        found_ssh=$((found_ssh + 1))
    done < <(journalctl \
        --since="$START_DATE $START_TIME" \
        --until="$END_DATE $END_TIME" \
        --no-pager -q \
        SYSLOG_IDENTIFIER=sshd 2>/dev/null)
fi

if [ "$found_ssh" -eq 0 ] && [ -f "$AUTH_LOG" ]; then
    while IFS= read -r line; do
        if echo "$line" | grep -qi "sshd"; then
            if echo "$line" | grep -q "Accepted"; then
                log_event "$GREEN" "SSH-OK " "$line"
                success_ssh=$((success_ssh + 1))
            elif echo "$line" | grep -q "Failed\|Invalid"; then
                log_event "$RED" "SSH-FAIL" "$line"
                failed_ssh=$((failed_ssh + 1))
            fi
            found_ssh=$((found_ssh + 1))
        fi
    done < <(grep_by_time "$AUTH_LOG")
fi

if [ "$found_ssh" -gt 0 ]; then
    echo ""
    log_info "  Summary: $success_ssh successful, $failed_ssh failed SSH attempts"
else
    log_none
fi


# SYSTEM REBOOTS AND SHUTDOWNS
print_section "System Reboots / Shutdowns"
found_reboots=0

if cmd_exists last; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == *"wtmp begins"* ]] && continue

        local line_date
        line_date=$(echo "$line" | awk '{print $5, $6, $7, $8}')
        local line_epoch
        line_epoch=$(date -d "$line_date" +%s 2>/dev/null)

        if [ -n "$line_epoch" ] && \
           [ "$line_epoch" -ge "$START_EPOCH" ] && \
           [ "$line_epoch" -le "$END_EPOCH" ]; then
            log_event "$RED" "REBOOT" "$line"
            found_reboots=$((found_reboots + 1))
        fi
    done < <(last reboot -F 2>/dev/null)
fi

if [ "$HAS_JOURNALD" = true ]; then
    while IFS= read -r line; do
        log_event "$RED" "SHUTDOWN" "$line"
        found_reboots=$((found_reboots + 1))
    done < <(journalctl \
        --since="$START_DATE $START_TIME" \
        --until="$END_DATE $END_TIME" \
        --no-pager -q \
        -u systemd-shutdown 2>/dev/null)
fi

[ "$found_reboots" -eq 0 ] && log_none


# BASH COMMAND HISTORY
print_section "Bash Command History"
found_bash=0

for histfile in /root/.bash_history /home/*/.bash_history; do
    [ ! -f "$histfile" ] && continue

    username=$(echo "$histfile" | grep -o 'home/[^/]*' | cut -d'/' -f2)
    [ -z "$username" ] && username="root"

    log_info "  Checking history for: $username"

    if grep -q "^#[0-9]\{10\}" "$histfile" 2>/dev/null; then
        current_epoch=""
        while IFS= read -r line; do
            if [[ "$line" =~ ^#([0-9]{10})$ ]]; then
                current_epoch="${BASH_REMATCH[1]}"
            elif [ -n "$current_epoch" ]; then
                if [ "$current_epoch" -ge "$START_EPOCH" ] && \
                   [ "$current_epoch" -le "$END_EPOCH" ]; then
                    ts=$(date -d "@$current_epoch" "+%Y-%m-%d %H:%M:%S")
                    log_event "$GREEN" "CMD   " "[$ts] ($username) $line"
                    found_bash=$((found_bash + 1))
                fi
                current_epoch=""
            fi
        done < "$histfile"
    else
        log_info "  No timestamps in history. Enable with: export HISTTIMEFORMAT='%F %T '"
        log_info "  Showing last 20 commands (unfiltered):"
        tail -20 "$histfile" | while IFS= read -r line; do
            log_event "$YELLOW" "CMD?  " "($username) $line"
            found_bash=$((found_bash + 1))
        done
    fi
done

[ "$found_bash" -eq 0 ] && log_none


# CRON JOB EXECUTIONS
print_section "Cron Job Executions"
found_cron=0

if [ "$HAS_JOURNALD" = true ]; then
    while IFS= read -r line; do
        log_event "$MAGENTA" "CRON  " "$line"
        found_cron=$((found_cron + 1))
    done < <(journalctl \
        --since="$START_DATE $START_TIME" \
        --until="$END_DATE $END_TIME" \
        --no-pager -q \
        SYSLOG_IDENTIFIER=cron 2>/dev/null)
fi

if [ "$found_cron" -eq 0 ] && [ -f "$SYSLOG" ]; then
    while IFS= read -r line; do
        if echo "$line" | grep -qi "cron\|CMD"; then
            log_event "$MAGENTA" "CRON  " "$line"
            found_cron=$((found_cron + 1))
        fi
    done < <(grep_by_time "$SYSLOG")
fi

[ "$found_cron" -eq 0 ] && log_none


# SOFTWARE INSTALLED / REMOVED
print_section "Software Installed / Removed"
log_info "  Searching for softwares installed or removed a (this may take some time)..."
found_packages=0

if [ -f "$DPKG_LOG" ]; then
    while IFS= read -r line; do
        if echo "$line" | grep -q "install\|remove\|upgrade"; then
            ts=$(echo "$line" | awk '{print $1, $2}')
            if in_range "$ts"; then
                log_event "$CYAN" "PKG   " "$line"
                found_packages=$((found_packages + 1))
            fi
        fi
    done < "$DPKG_LOG"
fi

for log in /var/log/dnf.log /var/log/yum.log; do
    if [ -f "$log" ]; then
        while IFS= read -r line; do
            log_event "$CYAN" "PKG   " "$line"
            found_packages=$((found_packages + 1))
        done < <(grep_by_time "$log")
    fi
done

if [ "$found_packages" -eq 0 ] && [ "$HAS_JOURNALD" = true ]; then
    while IFS= read -r line; do
        log_event "$CYAN" "PKG   " "$line"
        found_packages=$((found_packages + 1))
    done < <(journalctl \
        --since="$START_DATE $START_TIME" \
        --until="$END_DATE $END_TIME" \
        --no-pager -q \
        SYSLOG_IDENTIFIER=apt 2>/dev/null)
fi

[ "$found_packages" -eq 0 ] && log_none


# KERNEL / SYSTEM MESSAGES
print_section "Kernel & System Messages"
found_kernel=0

if [ "$HAS_JOURNALD" = true ]; then
    while IFS= read -r line; do
        log_event "$BLUE" "KERNEL" "$line"
        found_kernel=$((found_kernel + 1))
    done < <(journalctl \
        --since="$START_DATE $START_TIME" \
        --until="$END_DATE $END_TIME" \
        --no-pager -q \
        -k 2>/dev/null | head -30)
fi

[ "$found_kernel" -eq 0 ] && log_none


# FILES CREATED OR MODIFIED
print_section "Files Created / Modified in Time Range"
found_files=0

log_info "  Searching filesystem for modified files (this may take a moment)..."
SEARCH_DIRS=("/etc" "/home" "/root" "/tmp" "/var" "/usr/local/bin")

for dir in "${SEARCH_DIRS[@]}"; do
    [ ! -d "$dir" ] && continue

    while IFS= read -r filepath; do
        log_event "$MAGENTA" "FILE  " "$filepath"
        found_files=$((found_files + 1))
        [ "$found_files" -ge 50 ] && break
    done < <(find "$dir" \
        -newermt "$START_DATE $START_TIME" \
        ! -newermt "$END_DATE $END_TIME" \
        -not -path "*/proc/*" \
        -not -path "*/sys/*" \
        -not -path "*/.git/*" \
        -type f 2>/dev/null | head -50)
done

[ "$found_files" -eq 0 ] && log_none
[ "$found_files" -ge 50 ] && log_info "  (Results are limited to 50 per directory)"


# ACTIVE NETWORK CONNECTIONS
print_section "Current Network Connections (Snapshot)"
found_net=0

log_info "  Note: This shows connections at scan time, not historical data"
echo "" >> "$REPORT_FILE"

if cmd_exists ss; then
    log_info "  Active connections (ss):"
    while IFS= read -r line; do
        log_event "$CYAN" "NET   " "$line"
        found_net=$((found_net + 1))
    done < <(ss -tunp 2>/dev/null | grep ESTAB)
elif cmd_exists netstat; then
    while IFS= read -r line; do
        log_event "$CYAN" "NET   " "$line"
        found_net=$((found_net + 1))
    done < <(netstat -tunp 2>/dev/null | grep ESTABLISHED)
fi

[ "$found_net" -eq 0 ] && log_none


# FINAL SUMMARY
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║         FORENSIX SCAN COMPLETE           ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Time Range : ${RESET}$START_DATE $START_TIME → $END_DATE $END_TIME"
echo -e "  ${BOLD}Hostname   : ${RESET}$(hostname)"
echo -e "  ${BOLD}Total Events Found : ${GREEN}${BOLD}$FINDINGS${RESET}"
echo -e "  ${BOLD}Report saved to    : ${GREEN}$REPORT_FILE${RESET}"
echo ""

# Write summary to report too
{
    echo ""
    echo "========================================================"
    echo "  SCAN SUMMARY"
    echo "  Total Events : $FINDINGS"
    echo "  Completed    : $(date)"
    echo "========================================================"
} >> "$REPORT_FILE"
