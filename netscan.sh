#!/bin/bash

run_scan() {
    local target="$1"
    nmap -sV --script vuln "$target"
}

write_header() {
    local target="$1"

    echo "============================================================"
    echo "                NETWORK SECURITY SCAN REPORT"
    echo "============================================================"
    echo
    echo "Target IP Address/Hostname: $target"
    echo "Report Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo
}

write_ports_section() {
    local scan_results="$1"
    local open_ports

    echo "------------------------------------------------------------"
    echo "OPEN PORTS AND DETECTED SERVICES"
    echo "------------------------------------------------------------"

    open_ports=$(printf '%s\n' "$scan_results" |
        grep -E '^[0-9]+/(tcp|udp)[[:space:]]+open([[:space:]]|$)' || true)

    if [[ -n "$open_ports" ]]; then
        printf '%s\n' "$open_ports"
    else
        echo "No open ports detected."
    fi

    echo
}

query_nvd() {
    local product="$1"
    local version="$2"
    local results_limit=3
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0"
    local vulnerabilities_json
    local api_message
    local -a curl_options

    echo "Querying NVD for: $product $version"

    curl_options=(
        -sS
        --fail
        --connect-timeout 10
        --max-time 45
        --get
        "$nvd_api_url"
        --data-urlencode "keywordSearch=$product $version"
        --data-urlencode "resultsPerPage=$results_limit"
    )

    if [[ -n "${NVD_API_KEY:-}" ]]; then
        curl_options+=(-H "apiKey:${NVD_API_KEY}")
    fi

    if ! vulnerabilities_json=$(curl "${curl_options[@]}" 2>&1); then
        echo "  [!] Error: The NVD request failed."
        echo "  [!] curl response: $vulnerabilities_json"
        echo
        return
    fi

    if ! printf '%s\n' "$vulnerabilities_json" |
        jq -e . >/dev/null 2>&1; then
        echo "  [!] Error: NVD returned invalid JSON."
        echo
        return
    fi

    api_message=$(printf '%s\n' "$vulnerabilities_json" |
        jq -r '.message // empty')

    if [[ -n "$api_message" ]]; then
        echo "  [!] NVD API Error: $api_message"
        echo
        return
    fi

    if ! printf '%s\n' "$vulnerabilities_json" |
        jq -e '.vulnerabilities | length > 0' >/dev/null; then
        echo "  [+] No NVD keyword matches were found."
        echo
        return
    fi

    printf '%s\n' "$vulnerabilities_json" | jq -r '
        .vulnerabilities[] |

        ([.cve.descriptions[]? |
            select(.lang == "en") |
            .value][0] // "No English description available") as $description |

        (.cve.metrics.cvssMetricV40[0].cvssData.baseSeverity
            // .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
            // .cve.metrics.cvssMetricV30[0].cvssData.baseSeverity
            // .cve.metrics.cvssMetricV2[0].baseSeverity
            // "N/A") as $severity |

        (.cve.metrics.cvssMetricV40[0].cvssData.baseScore
            // .cve.metrics.cvssMetricV31[0].cvssData.baseScore
            // .cve.metrics.cvssMetricV30[0].cvssData.baseScore
            // .cve.metrics.cvssMetricV2[0].cvssData.baseScore
            // "N/A") as $score |

        "  CVE ID: \(.cve.id)\n" +
        "  Description: \($description | gsub("\n"; " "))\n" +
        "  Severity: \($severity)\n" +
        "  Base Score: \($score)\n" +
        "  Reference: https://nvd.nist.gov/vuln/detail/\(.cve.id)\n" +
        "  ----------------------------------------------------------"
    '

    echo
}

write_vulns_section() {
    local scan_results="$1"
    local nse_findings
    local version_match_found="false"
    local line
    local product_name
    local product_version
    local query_count=0
    local max_nvd_queries=2
    local queried_services="|"

    echo "------------------------------------------------------------"
    echo "POTENTIAL VULNERABILITIES IDENTIFIED"
    echo "------------------------------------------------------------"

    echo "High-Confidence NSE Results:"
    echo

    nse_findings=$(printf '%s\n' "$scan_results" |
        grep -i 'VULNERABLE' |
        grep -Eiv 'NOT[[:space:]_-]*VULNERABLE' || true)

    if [[ -n "$nse_findings" ]]; then
        printf '%s\n' "$nse_findings"
    else
        echo "No positive NSE vulnerability findings were reported."
    fi

    echo
    echo "Local Service Version Analysis:"
    echo

    while IFS= read -r line; do
        [[ "$line" =~ ^[0-9]+/(tcp|udp)[[:space:]]+open ]] || continue

        case "$line" in
            *"vsftpd 2.3.4"*)
                if [[ "$line" =~ vsftpd[[:space:]]+2\.3\.4([[:space:]]|$) ]]; then
                    echo "[!!] POTENTIAL VULNERABILITY: vsftpd 2.3.4 may contain a known backdoor."
                    echo "     CVE: CVE-2011-2523"
                    echo "     Reference: https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
                    version_match_found="true"
                fi
                ;;

            *"Apache httpd 2.4.49"*)
                if [[ "$line" =~ Apache[[:space:]]+httpd[[:space:]]+2\.4\.49([[:space:]]|$) ]]; then
                    echo "[!!] POTENTIAL VULNERABILITY: Apache HTTP Server 2.4.49 may be vulnerable to path traversal."
                    echo "     CVE: CVE-2021-41773"
                    echo "     Reference: https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
                    version_match_found="true"
                fi
                ;;

            *"ProFTPD 1.3.5"*)
                if [[ "$line" =~ ProFTPD[[:space:]]+1\.3\.5([[:space:]]|$) ]]; then
                    echo "[!!] POTENTIAL VULNERABILITY: ProFTPD 1.3.5 with mod_copy enabled may permit unauthorized file access."
                    echo "     CVE: CVE-2015-3306"
                    echo "     Reference: https://nvd.nist.gov/vuln/detail/CVE-2015-3306"
                    version_match_found="true"
                fi
                ;;

            *"UnrealIRCd 3.2.8.1"*)
                if [[ "$line" =~ UnrealIRCd[[:space:]]+3\.2\.8\.1([[:space:]]|$) ]]; then
                    echo "[!!] POTENTIAL VULNERABILITY: Certain UnrealIRCd 3.2.8.1 distributions contained a backdoor."
                    echo "     CVE: CVE-2010-2075"
                    echo "     Reference: https://nvd.nist.gov/vuln/detail/CVE-2010-2075"
                    version_match_found="true"
                fi
                ;;
        esac
    done <<< "$scan_results"

    if [[ "$version_match_found" == "false" ]]; then
        echo "No locally configured vulnerable versions were detected."
    fi

    echo
    echo "Live NVD Keyword Results:"
    echo "NVD results are potential matches and require validation."
    echo

    while IFS= read -r line; do
        [[ "$line" =~ ^[0-9]+/(tcp|udp)[[:space:]]+open ]] || continue

        product_name=""
        product_version=""

        case "$line" in
            *"OpenSSH "*)
                product_name="OpenSSH"
                product_version=$(sed -nE \
                    's/.*OpenSSH[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$line")
                ;;

            *"Apache httpd "*)
                product_name="Apache httpd"
                product_version=$(sed -nE \
                    's/.*Apache httpd[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$line")
                ;;

            *"nginx "*)
                product_name="nginx"
                product_version=$(sed -nE \
                    's/.*nginx[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$line")
                ;;

            *"vsftpd "*)
                product_name="vsftpd"
                product_version=$(sed -nE \
                    's/.*vsftpd[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$line")
                ;;

            *"ProFTPD "*)
                product_name="ProFTPD"
                product_version=$(sed -nE \
                    's/.*ProFTPD[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$line")
                ;;

            *"UnrealIRCd "*)
                product_name="UnrealIRCd"
                product_version=$(sed -nE \
                    's/.*UnrealIRCd[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$line")
                ;;
        esac

        if [[ -z "$product_name" || -z "$product_version" ]]; then
            continue
        fi

        if [[ "$queried_services" == *"|$product_name $product_version|"* ]]; then
            continue
        fi

        if (( query_count >= max_nvd_queries )); then
            break
        fi

        if (( query_count > 0 )); then
            sleep 6
        fi

        query_nvd "$product_name" "$product_version"

        queried_services+="$product_name $product_version|"
        query_count=$((query_count + 1))
    done <<< "$scan_results"

    if (( query_count == 0 )); then
        echo "No supported product and version combinations were available for an NVD query."
        echo
    fi

    echo "NVD Notice: This product uses data from the NVD API but is not endorsed or certified by the NVD."
    echo
}

write_recs_section() {
    echo "------------------------------------------------------------"
    echo "RECOMMENDATIONS FOR REMEDIATION"
    echo "------------------------------------------------------------"
    echo "1. Validate all detected vulnerabilities before remediation."
    echo "2. Update affected software and services to supported versions."
    echo "3. Change default credentials and use strong authentication."
    echo "4. Restrict unnecessary ports with host and network firewalls."
    echo "5. Disable services that are not operationally required."
    echo
}

write_footer() {
    echo "============================================================"
    echo "                         END OF REPORT"
    echo "============================================================"
}

check_dependencies() {
    local required_command
    local missing="false"

    for required_command in nmap curl jq; do
        if ! command -v "$required_command" >/dev/null 2>&1; then
            echo "Error: Required command '$required_command' is not installed." >&2
            missing="true"
        fi
    done

    if [[ "$missing" == "true" ]]; then
        echo "Install the missing dependencies and try again." >&2
        return 1
    fi
}

main() {
    if [[ "$#" -ne 1 ]]; then
        echo "Usage: $0 <target_ip_or_hostname>" >&2
        exit 1
    fi

    local target="$1"
    local report_file
    local scan_results
    local scan_status

    if [[ "$target" == -* ]]; then
        echo "Error: The target cannot begin with a hyphen." >&2
        exit 1
    fi

    check_dependencies || exit 1

    report_file="report_$(date '+%Y%m%d_%H%M%S').txt"

    echo "Authorized security testing only."
    echo "Scanning $target with Nmap and NSE vulnerability scripts."
    echo "This scan may take several minutes."

    scan_results=$(run_scan "$target" 2>&1)
    scan_status=$?

    if [[ "$scan_status" -ne 0 ]]; then
        echo "Error: The Nmap scan failed." >&2
        printf '%s\n' "$scan_results" >&2
        exit 1
    fi

    write_header "$target" > "$report_file"
    write_ports_section "$scan_results" >> "$report_file"
    write_vulns_section "$scan_results" >> "$report_file"
    write_recs_section >> "$report_file"
    write_footer >> "$report_file"

    echo "Scan completed."
    echo "Report created: $report_file"
}

main "$@"
