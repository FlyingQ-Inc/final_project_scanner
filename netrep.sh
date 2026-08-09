#!/bin/bash

write_header() {
    local target="$1"

    echo "============================================================"
    echo "                NETWORK SECURITY SCAN REPORT"
    echo "============================================================"
    echo
    echo "Target IP Address/Hostname: $target"
    echo "Report Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo
}

write_ports_section() {
    echo "------------------------------------------------------------"
    echo "OPEN PORTS AND DETECTED SERVICES"
    echo "------------------------------------------------------------"
    echo "Port 22/tcp  - ssh"
    echo "Port 80/tcp  - http"
    echo "Port 443/tcp - https"
    echo
}

write_vulns_section() {
    echo "------------------------------------------------------------"
    echo "POTENTIAL VULNERABILITIES IDENTIFIED"
    echo "------------------------------------------------------------"
    echo "CVE-2023-XXXX       - Outdated web server software"
    echo "Default Credentials - FTP server may use default credentials"
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

    local target="$1"
    local REPORT_FILE="report.txt"

    write_header "$target" > "$REPORT_FILE"
    write_ports_section >> "$REPORT_FILE"
    write_vulns_section >> "$REPORT_FILE"
    write_recs_section >> "$REPORT_FILE"
    write_footer >> "$REPORT_FILE"

    echo "Report successfully created: $REPORT_FILE"
}

main "$@"
