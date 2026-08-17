cat > netrep.sh <<'EOF'
#!/bin/bash

run_scan() {
    local TARGET="$1"
    nmap -sV --script vuln "$TARGET"
}

write_header() {
    local TARGET="$1"

    echo "============================================================"
    echo "                NETWORK SECURITY SCAN REPORT"
    echo "============================================================"
    echo
    echo "Target IP Address/Hostname: $TARGET"
    echo "Report Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo
}

write_ports_section() {
    local SCAN_RESULTS="$1"

    echo "------------------------------------------------------------"
    echo "OPEN PORTS AND DETECTED SERVICES"
    echo "------------------------------------------------------------"

    echo "$SCAN_RESULTS" |
        grep -E '^[0-9]+/(tcp|udp)[[:space:]]+open'

    echo
}

write_vulns_section() {
    local SCAN_RESULTS="$1"
    local VERSION_MATCH_FOUND="false"

    echo "------------------------------------------------------------"
    echo "POTENTIAL VULNERABILITIES IDENTIFIED"
    echo "------------------------------------------------------------"

    echo "High-Confidence NSE Results:"
    echo

    if echo "$SCAN_RESULTS" | grep -q "VULNERABLE"; then
        echo "$SCAN_RESULTS" | grep "VULNERABLE"
    else
        echo "No high-confidence NSE vulnerabilities were reported."
    fi

    echo
    echo "Service Version Analysis:"
    echo

    while IFS= read -r line; do
        case "$line" in
            *"vsftpd 2.3.4"*)
                echo "[!!] VULNERABILITY DETECTED: vsftpd 2.3.4 contains a known critical backdoor."
                VERSION_MATCH_FOUND="true"
                ;;

            *"Apache httpd 2.4.49"*)
                echo "[!!] VULNERABILITY DETECTED: Apache 2.4.49 may be vulnerable to path traversal."
                echo "     Related vulnerability: CVE-2021-41773"
                VERSION_MATCH_FOUND="true"
                ;;

            *"ProFTPD 1.3.5"*)
                echo "[!!] VULNERABILITY DETECTED: ProFTPD 1.3.5 may be vulnerable through its mod_copy module."
                echo "     Related vulnerability: CVE-2015-3306"
                VERSION_MATCH_FOUND="true"
                ;;

            *"UnrealIRCd 3.2.8.1"*)
                echo "[!!] VULNERABILITY DETECTED: UnrealIRCd 3.2.8.1 may contain a known backdoor."
                VERSION_MATCH_FOUND="true"
                ;;
        esac
    done <<< "$SCAN_RESULTS"

    if [ "$VERSION_MATCH_FOUND" = "false" ]; then
        echo "No manually configured vulnerable service versions were detected."
    fi

    echo
}

write_recs_section() {
    echo "------------------------------------------------------------"
    echo "RECOMMENDATIONS FOR REMEDIATION"
    echo "------------------------------------------------------------"
    echo "1. Update all software and services to the latest versions."
    echo "2. Investigate all vulnerabilities reported by NSE."
    echo "3. Change all default credentials immediately."
    echo "4. Implement and properly configure a firewall."
    echo "5. Disable unnecessary ports and services."
    echo
}

write_footer() {
    echo "============================================================"
    echo "                         END OF REPORT"
    echo "============================================================"
}

main() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <target_ip_or_hostname>" >&2
        exit 1
    fi

    if ! command -v nmap >/dev/null 2>&1; then
        echo "Error: nmap is not installed." >&2
        exit 1
    fi

    local TARGET="$1"
    local REPORT_FILE="report.txt"
    local SCAN_RESULTS
    local SCAN_STATUS

    echo "Scanning $TARGET..."
    echo "The vulnerability scan may take several minutes."

    SCAN_RESULTS=$(run_scan "$TARGET" 2>&1)
    SCAN_STATUS=$?

    if [ "$SCAN_STATUS" -ne 0 ]; then
        echo "Error: The Nmap scan failed." >&2
        echo "$SCAN_RESULTS" >&2
        exit 1
    fi

    write_header "$TARGET" > "$REPORT_FILE"
    write_ports_section "$SCAN_RESULTS" >> "$REPORT_FILE"
    write_vulns_section "$SCAN_RESULTS" >> "$REPORT_FILE"
    write_recs_section >> "$REPORT_FILE"
    write_footer >> "$REPORT_FILE"

    echo "Scan completed."
    echo "Report created: $REPORT_FILE"
}

main "$@"
EOF
