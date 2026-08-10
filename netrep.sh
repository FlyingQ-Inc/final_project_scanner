#!/bin/bash

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
    local TARGET="$1"

    echo "------------------------------------------------------------"
    echo "OPEN PORTS AND DETECTED SERVICES"
    echo "------------------------------------------------------------"

    nmap -sV "$TARGET" | grep "open"

    echo
}

write_vulns_section() {
    echo "------------------------------------------------------------"
    echo "POTENTIAL VULNERABILITIES IDENTIFIED"
    echo "------------------------------------------------------------"
    echo "CVE-2023-XXXX       - Outdated web server software"
    echo "Default Credentials - Server may use default credentials"
    echo "Weak Encryption     - Service may support outdated protocols"
    echo
}

write_recs_section() {
    echo "------------------------------------------------------------"
    echo "RECOMMENDATIONS FOR REMEDIATION"
    echo "------------------------------------------------------------"
    echo "1. Update all software and services to the latest versions."
    echo "2. Change all default credentials immediately."
    echo "3. Implement and properly configure a firewall."
    echo "4. Disable unnecessary ports and services."
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

    local TARGET="$1"
    local REPORT_FILE="report.txt"

    write_header "$TARGET" > "$REPORT_FILE"
    write_ports_section "$TARGET" >> "$REPORT_FILE"
    write_vulns_section >> "$REPORT_FILE"
    write_recs_section >> "$REPORT_FILE"
    write_footer >> "$REPORT_FILE"

    echo "Scan completed."
    echo "Report created: $REPORT_FILE"
}

main "$@"
