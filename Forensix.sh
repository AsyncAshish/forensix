#!/bin/bash

# colors
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
CYAN='\e[0;36m'
BLUE='\e[0;34m'
MAGENTA='\e[0;35m'
BOLD='\e[1m'
RESET='\e[0m'

# vars
START_DATE=""
END_DATE=""
START_TIME=""
END_TIME=""
FINDINGS=0   

# to epoch
to_epoch() {
    date -d "$1 $2" +%s
}

print_section() {
    echo ""
    echo -e "${BLUE}${BOLD}--- $1 ---${RESET}"
    echo "" >> "$REPORT_FILE"
    echo "================================================" >> "$REPORT_FILE"
    echo "  $1" >> "$REPORT_FILE"
    echo "================================================" >> "$REPORT_FILE"
}

log_event() {
    echo -e "  ${1}${2}${RESET} $3"
    echo "  [$2] $3" >> "$REPORT_FILE"
    FINDINGS=$((FINDINGS + 1))
}

log_none() {
    echo -e "  ${YELLOW}Nothing found here.${RESET}"
    echo "  [--] Nothing found here." >> "$REPORT_FILE"
}


clear
echo -e "${CYAN}======================================================${RESET}${BLUE}"
figlet "        Forensix"
echo -e "${RESET}${CYAN}======================================================${RESET}"
echo ""
echo -e "     ${BOLD}Forensix v1.0${RESET}"
echo -e "     ${YELLOW}Author : Ashish${RESET}"
echo -e "     ${YELLOW}Website: kernyxlabs.in${RESET}"
echo ""
echo -e "${CYAN}======================================================${RESET}"
echo ""

# need root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}bro you need to run this with sudo${RESET}"
    exit 1
fi

# log paths
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"
DPKG_LOG="/var/log/dpkg.log"

echo -e "${GREEN}Set time range (press enter for last 24 hours):${RESET}"
echo ""
# defaults
NOW_DATE=$(date +"%Y-%m-%d")
YEST=$(date -d "yesterday" +"%Y-%m-%d")

echo -e "${BLUE}Start date (YYYY-MM-DD) [default: $YEST]:${RESET}"
read INPUT_START_DATE
if [ "$INPUT_START_DATE" == "" ]; then
  START_DATE=$YEST
else
  START_DATE=$INPUT_START_DATE
fi

echo -e "${BLUE}Start time (HH:MM:SS) [default: 00:00:00]:${RESET}"
read INPUT_START_TIME
if [ "$INPUT_START_TIME" == "" ]; then
  START_TIME="00:00:00"
else
  START_TIME=$INPUT_START_TIME
fi

echo -e "${BLUE}End date (YYYY-MM-DD) [default: $NOW_DATE]:${RESET}"
read INPUT_END_DATE
if [ "$INPUT_END_DATE" == "" ]; then
  END_DATE=$NOW_DATE
else
  END_DATE=$INPUT_END_DATE
fi

echo -e "${BLUE}End time (HH:MM:SS) [default: 23:59:59]:${RESET}"
read INPUT_END_TIME
if [ "$INPUT_END_TIME" == "" ]; then
  END_TIME="23:59:59"
else
  END_TIME=$INPUT_END_TIME
fi

# validate formats so the script doesnt break
if [[ ! "$START_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || [[ ! "$END_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo -e "${RED}[!] Bro, wrong date format! Use YYYY-MM-DD. Exiting...${RESET}"
    exit 1
fi

if [[ ! "$START_TIME" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || [[ ! "$END_TIME" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
    echo -e "${RED}[!] Bro, wrong time format! Use HH:MM:SS. Exiting...${RESET}"
    exit 1
fi

# convert bounds
START_EPOCH=`date -d "$START_DATE $START_TIME" +%s`
END_EPOCH=`date -d "$END_DATE $END_TIME" +%s`

# auth logs use a weird date format like "Jun 23" instead of 2026-06-23
# so doing this to make grep work later
AUTH_DATE=$(date -d "$START_DATE" "+%b %_d")

# check if end time is actually after start time
if [ "$END_EPOCH" -le "$START_EPOCH" ]; then
    echo -e "${RED}[!] The end time is before the start time. That makes no sense. Exiting...${RESET}"
    exit 1
fi

echo -e "\n${CYAN}[*] Dates look good. Initializing scanner...${RESET}"
sleep 3
clear

echo -e "${CYAN}==============================================${RESET}"
echo -e "${BOLD}   SCANNING SYSTEM...${RESET}"
echo -e "${CYAN}==============================================${RESET}"
echo ""

# setup report
mkdir -p forensic_reports
REPORT_FILE="forensic_reports/report_$(date +%s).txt"

echo "Report generated on $(date)" > "$REPORT_FILE"
echo "Target: $(hostname)" >> "$REPORT_FILE"
echo "Time: $START_DATE to $END_DATE" >> "$REPORT_FILE"
echo "---------------------------" >> "$REPORT_FILE"

echo -e "${GREEN}Saving to $REPORT_FILE${RESET}"
echo ""


# ==============================
# LOGINS
# ==============================
print_section "User Logins"
echo ""
found_logins=0

while IFS= read -r line; do
    if [[ -z "$line" ]]; then continue; fi
    if [[ "$line" == *"wtmp begins"* ]]; then continue; fi
    if [[ "$line" == *"reboot"* ]]; then continue; fi

    line_date=$(echo "$line" | awk '{print $5, $6, $7, $8}')
    line_epoch=$(date -d "$line_date" +%s)

    # nested if statements are easier to read
    if [ "$line_epoch" -ge "$START_EPOCH" ]; then
        if [ "$line_epoch" -le "$END_EPOCH" ]; then
            log_event "$GREEN" "LOGIN" "$line"
            found_logins=$((found_logins + 1))
        fi
    fi
done < <(last -F)

if [ "$found_logins" -eq 0 ]; then
  log_none
fi


# ==============================
#  SUDO COMMANDS
# ==============================
print_section "Sudo Usage"
echo ""
found_sudo=0

# just grepping the journal
journalctl --since="$START_DATE $START_TIME" --until="$END_DATE $END_TIME" --no-pager | grep "sudo" | while read -r line; do
    log_event "$YELLOW" "SUDO" "$line"
    found_sudo=$((found_sudo + 1))
done

# also check auth.log
if [ -f "$AUTH_LOG" ]; then
    cat "$AUTH_LOG" | grep "$AUTH_DATE" | grep "sudo" | while read -r line; do
        log_event "$YELLOW" "SUDO" "$line"
        found_sudo=$((found_sudo + 1))
    done
fi

if [ "$found_sudo" -eq 0 ]; then log_none; fi


# ==============================
# SSH LOGINS
# ==============================
print_section "SSH Attempts"
echo ""
found_ssh=0

if [ -f "$AUTH_LOG" ]; then
    cat "$AUTH_LOG" | grep "$AUTH_DATE" | grep -i "sshd" | while read -r line; do
        if echo "$line" | grep -q "Accepted"; then
            log_event "$GREEN" "SSH-OK " "$line"
            found_ssh=$((found_ssh + 1))
        elif echo "$line" | grep -q "Failed\|Invalid"; then
            log_event "$RED" "SSH-FAIL" "$line"
            found_ssh=$((found_ssh + 1))
        fi
    done
fi

if [ "$found_ssh" -eq 0 ]; then
    log_none
fi


# ==============================
# REBOOTS
# ==============================
print_section "Reboots"
echo ""
found_reboots=0

while IFS= read -r line; do
    if [[ -z "$line" ]]; then continue; fi
    if [[ "$line" == *"wtmp begins"* ]]; then continue; fi

    line_date=$(echo "$line" | awk '{print $5, $6, $7, $8}')
    line_epoch=$(date -d "$line_date" +%s)

    if [ "$line_epoch" -ge "$START_EPOCH" ]; then
        if [ "$line_epoch" -le "$END_EPOCH" ]; then
            log_event "$RED" "REBOOT" "$line"
            found_reboots=$((found_reboots + 1))
        fi
    fi
done < <(last reboot -F)

if [ "$found_reboots" -eq 0 ]; then
    log_none
fi


# ==============================
# BASH HISTORY
# ==============================
print_section "Terminal History"
echo ""
found_bash=0

for histfile in /root/.bash_history /home/*/.bash_history; do
    if [ ! -f "$histfile" ]; then continue; fi

    username=$(echo "$histfile" | cut -d'/' -f3)
    if [ "$username" == ".bash_history" ]; then username="root"; fi

    CMD_TIME="unknown time"
    
    cat "$histfile" | tail -n 50 | while read -r line; do
        # check if it starts with a # which means its a timestamp
        if echo "$line" | grep -q "^#"; then
            # remove the # symbol to get the number
            RAW_TS=$(echo "$line" | cut -c 2-)
            CMD_TIME=$(date -d "@$RAW_TS" "+%Y-%m-%d %H:%M:%S")
        else
            log_event "$GREEN" "CMD   " "[$CMD_TIME] ($username) $line"
            found_bash=$((found_bash + 1))
        fi
    done
done

if [ "$found_bash" -eq 0 ]; then log_none; fi


# ==============================
# INSTALLED PACKAGES
# ==============================
print_section "Apt Packages"
echo ""
found_packages=0

if [ -f "$DPKG_LOG" ]; then
    cat "$DPKG_LOG" | grep "$START_DATE" | grep -e "install" -e "remove" | while read -r line; do
        log_event "$CYAN" "PKG   " "$line"
        found_packages=$((found_packages + 1))
    done
fi

if [ "$found_packages" -eq 0 ]; then
    log_none
fi


# ==============================
# MODIFIED FILES
# ==============================
print_section "Modified Files"
echo -e " ${RED}searching for recently modified files in /etc and /var ( this might take a minute )${RESET} "
echo ""
found_files=0

for dir in "/etc" "/home" "/root" "/var/www"; do
    if [ ! -d "$dir" ]; then continue; fi

    while IFS= read -r filepath; do
        log_event "$MAGENTA" "FILE  " "$filepath"
        found_files=$((found_files + 1))
    done < <(find "$dir" -newermt "$START_DATE $START_TIME" ! -newermt "$END_DATE $END_TIME" -not -path "*/proc/*" -not -path "*/sys/*" -type f)
done

if [ "$found_files" -eq 0 ]; then log_none; fi


# ==============================
#  NETWORK CONNECTIONS
# ==============================
print_section "Network (Current)"
found_net=0

while IFS= read -r line; do
    log_event "$CYAN" "NET   " "$line"
    found_net=$((found_net + 1))
done < <(netstat -tunp | grep ESTABLISHED)

if [ "$found_net" -eq 0 ]; then log_none; fi



echo ""
echo -e "${CYAN}${BOLD}============================================${RESET}"
echo -e "${CYAN}${BOLD}          FORENSIC SCAN COMPLETE            ${RESET}"
echo -e "${CYAN}${BOLD}============================================${RESET}"
echo ""
echo -e "  ${BOLD}Time Range : ${RESET}$START_DATE $START_TIME → $END_DATE $END_TIME"
echo -e "  ${BOLD}Hostname   : ${RESET}$(hostname)"
echo -e "  ${BOLD}Total events found : ${GREEN}${BOLD}$FINDINGS${RESET}"
echo -e "  ${BOLD}Report saved to    : ${GREEN}$REPORT_FILE${RESET}"
echo ""

echo "Total events: $FINDINGS" >> "$REPORT_FILE"
