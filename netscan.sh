#!/bin/bash
# Network Vulnerability Scanner and Report Generator
# Author: Caleb Quisenberry | Course: NTS370
# Scan only systems you own or have explicit permission to assess.

set -o pipefail

TARGET=""
REPORT_FILE=""
PORTS=""
USE_NVD=1
USE_OS=0
USE_HTML=0
SKIP_DISCOVERY=0
SCAN_RESULTS=""
SCAN_COMMAND=""
NVD_DELAY_SECONDS="${NVD_DELAY_SECONDS:-6}"
declare -a OPEN_PORTS=() FINDINGS=() RECOMMENDATIONS=() NVD_MESSAGES=()
declare -A SEEN_FINDINGS=() SEEN_RECOMMENDATIONS=()

# Explain options without requiring Nmap or an API connection.
usage() {
    printf '%s\n' \
        "Usage: $0 [-H] [-n] [-O] [-P] [-o report.txt] [-p ports] <target>" \
        "  -h         Display help." \
        "  -H         Also generate an HTML report." \
        "  -n         Disable NVD API lookups." \
        "  -O         Enable OS detection; requires root." \
        "  -P         Skip host discovery with -Pn." \
        "  -o FILE    Choose a .txt report filename." \
        "  -p PORTS   Select ports, such as 22,80,443 or 1-1024."
}

# Permit single ports and ranges while rejecting values outside 1 through 65535.
valid_ports() {
    local item first last
    local -a selections
    [[ "$1" =~ ^[0-9,-]+$ ]] || return 1
    IFS=',' read -r -a selections <<< "$1"
    for item in "${selections[@]}"; do
        [[ "$item" =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]] || return 1
        first="${item%-*}"
        last="${item#*-}"
        (( 10#$first >= 1 && 10#$last <= 65535 && 10#$first <= 10#$last )) || return 1
    done
}

# getopts supports enhancements without weakening the one-target requirement.
parse_arguments() {
    local option
    while getopts ":hHnOPo:p:" option; do
        case "$option" in
            h) usage; exit 0 ;;
            H) USE_HTML=1 ;;
            n) USE_NVD=0 ;;
            O) USE_OS=1 ;;
            P) SKIP_DISCOVERY=1 ;;
            o) REPORT_FILE="$OPTARG" ;;
            p) PORTS="$OPTARG" ;;
            :) printf 'Error: -%s requires an argument.\n' "$OPTARG" >&2; usage >&2; return 1 ;;
            \?) printf 'Error: Unknown option -%s.\n' "$OPTARG" >&2; usage >&2; return 1 ;;
        esac
    done
    shift $((OPTIND - 1))
    if (( $# != 1 )); then
        echo "Error: Provide exactly one target IP address or hostname." >&2
        usage >&2
        return 1
    fi
    TARGET="$1"
    if [[ -z "$TARGET" || "$TARGET" == -* || "$TARGET" =~ [[:space:]] ]]; then
        echo "Error: Invalid target IP address or hostname." >&2
        return 1
    fi
    if [[ -n "$PORTS" ]] && ! valid_ports "$PORTS"; then
        echo "Error: Invalid port selection; use 22,80,443 or 1-1024." >&2
        return 1
    fi
    if (( USE_OS && EUID != 0 )); then
        echo "Error: OS detection requires root. Run the command with sudo." >&2
        return 1
    fi
    [[ -n "$REPORT_FILE" ]] || REPORT_FILE="report_$(date '+%Y%m%d_%H%M%S').txt"
    if [[ "$REPORT_FILE" != *.txt || -d "$REPORT_FILE" ]]; then
        echo "Error: The output filename must be a writable .txt file." >&2
        return 1
    fi
    [[ "$NVD_DELAY_SECONDS" =~ ^[0-9]+$ ]] || NVD_DELAY_SECONDS=6
}

# curl and jq are optional only when the explicit offline flag is selected.
check_dependencies() {
    local dependency missing=0
    local -a required=(nmap)
    (( USE_NVD == 0 )) || required+=(curl jq)
    for dependency in "${required[@]}"; do
        if ! command -v "$dependency" >/dev/null 2>&1; then
            printf "Error: Required dependency '%s' is not installed.\n" "$dependency" >&2
            missing=1
        fi
    done
    if (( missing )); then
        echo "Install dependencies with: sudo apt install nmap curl jq" >&2
        return 1
    fi
}

# Deduplicate CVE IDs and recommendations across local, NSE, and NVD analysis.
add_finding() {
    local id="$1" severity="$2" service="$3" description="$4"
    local recommendation="$5" source="$6" reference="${7:-N/A}"
    [[ -z "${SEEN_FINDINGS[$id]+found}" ]] || return 0
    SEEN_FINDINGS["$id"]=1
    FINDINGS+=("$id"$'\t'"$severity"$'\t'"$service"$'\t'"$description"$'\t'"$source"$'\t'"$reference")
    if [[ -z "${SEEN_RECOMMENDATIONS[$recommendation]+found}" ]]; then
        SEEN_RECOMMENDATIONS["$recommendation"]=1
        RECOMMENDATIONS+=("$recommendation")
    fi
}

# Build Nmap arguments as an array, execute one scan, and preserve its status.
run_scan() {
    local status
    local -a command=(nmap -sV --script vuln --script-timeout 30s --host-timeout 10m --reason)
    [[ -z "$PORTS" ]] || command+=(-p "$PORTS")
    (( USE_OS == 0 )) || command+=(-O --osscan-limit)
    (( SKIP_DISCOVERY == 0 )) || command+=(-Pn)
    command+=("$TARGET")
    printf -v SCAN_COMMAND '%q ' "${command[@]}"
    echo "Scanning $TARGET. Vulnerability scripts can take several minutes..."
    SCAN_RESULTS=$("${command[@]}" 2>&1)
    status=$?
    if (( status != 0 )); then
        printf 'Error: Nmap failed with exit status %s.\n%s\n' "$status" "$SCAN_RESULTS" >&2
        return 1
    fi
    if grep -Eq '0 hosts up|Failed to resolve|No targets were specified' <<< "$SCAN_RESULTS"; then
        echo "Error: Nmap could not reach or resolve the target." >&2
        return 1
    fi
    # Anchoring excludes CPE values and NSE descriptions that merely mention ports.
    mapfile -t OPEN_PORTS < <(grep -E '^[0-9]+/(tcp|udp)[[:space:]]+open([[:space:]]|$)' \
        <<< "$SCAN_RESULTS" || true)
}

# Exposed services are labeled as risks, not automatically claimed as CVEs.
analyze_exposure() {
    local row port service id severity description recommendation
    for row in "${OPEN_PORTS[@]}"; do
        read -r port _ service _ <<< "$row"
        id="EXPOSURE-$port"
        case "${port%/*}" in
            21) severity=HIGH; description="FTP may transmit credentials and data without encryption."
                recommendation="Disable FTP or replace it with SFTP; remove anonymous access." ;;
            22) severity=LOW; description="SSH is remotely accessible and should be hardened."
                recommendation="Restrict SSH to approved addresses, disable root login, and require key authentication." ;;
            23) severity=CRITICAL; description="Telnet exposes unencrypted remote login credentials."
                recommendation="Disable Telnet and replace it with SSH." ;;
            80|8000|8080) severity=MEDIUM; description="Unencrypted HTTP can expose sessions or application data."
                recommendation="Enable HTTPS, redirect HTTP to TLS, and apply secure web-server settings." ;;
            111) severity=MEDIUM; description="rpcbind exposes RPC service enumeration."
                recommendation="Disable unnecessary rpcbind services or restrict them to trusted hosts." ;;
            139|445) severity=HIGH; description="SMB exposure can enable enumeration, lateral movement, or legacy-protocol abuse."
                recommendation="Restrict SMB to trusted networks, disable SMBv1, and apply current patches." ;;
            1433|1521|3306|5432) severity=HIGH; description="A database service is accessible over the network."
                recommendation="Bind databases to approved interfaces, require strong authentication, and restrict firewall access." ;;
            2049) severity=HIGH; description="NFS may expose sensitive file exports."
                recommendation="Limit NFS exports to authorized clients and require appropriate authentication." ;;
            2375) severity=CRITICAL; description="An unencrypted Docker API can permit host-level control."
                recommendation="Disable Docker TCP port 2375 or require mutually authenticated TLS." ;;
            3389) severity=HIGH; description="RDP exposure increases credential-attack and remote-access risk."
                recommendation="Place RDP behind a VPN, enforce MFA, enable Network Level Authentication, and patch Windows." ;;
            5900|5901) severity=HIGH; description="VNC remote-desktop access may expose weak or unencrypted authentication."
                recommendation="Restrict VNC to a VPN or SSH tunnel and require strong authentication." ;;
            6379) severity=CRITICAL; description="Redis network access may expose data or administrative commands."
                recommendation="Bind Redis to trusted interfaces, enable authentication, and block public access." ;;
            9200) severity=HIGH; description="Elasticsearch may expose indexes and administrative APIs."
                recommendation="Require Elasticsearch authentication, enable TLS, and restrict API access." ;;
            27017) severity=HIGH; description="MongoDB network access may expose databases without adequate controls."
                recommendation="Enable MongoDB authentication, bind to trusted interfaces, and restrict firewall rules." ;;
            *) continue ;;
        esac
        add_finding "$id" "$severity" "$port $service" "$description" "$recommendation" "Service exposure analysis"
    done
}

# Match documented affected software versions while avoiding suffix overmatches.
analyze_versions() {
    local row port patch major minor version
    for row in "${OPEN_PORTS[@]}"; do
        read -r port _ <<< "$row"
        if [[ "$row" =~ vsftpd[[:space:]]+2\.3\.4([[:space:]]|$) ]]; then
            add_finding CVE-2011-2523 CRITICAL "$port vsftpd 2.3.4" \
                "A compromised vsftpd 2.3.4 distribution contains a remote backdoor." \
                "Remove vsftpd 2.3.4 and install a current verified release." "Local version rule" \
                "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
        fi
        if [[ "$row" =~ ProFTPD[[:space:]]+1\.3\.5([[:space:]]|$) ]]; then
            add_finding CVE-2015-3306 HIGH "$port ProFTPD 1.3.5" \
                "The ProFTPD mod_copy module may permit unauthorized file-copy operations." \
                "Upgrade ProFTPD, disable mod_copy, and verify that patched suffix releases are correctly identified." \
                "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2015-3306"
        fi
        if [[ "$row" =~ Apache[[:space:]]+httpd[[:space:]]+2\.4\.([0-9]+)([[:space:]]|$) ]]; then
            patch="${BASH_REMATCH[1]}"
            if (( 10#$patch <= 48 )); then
                add_finding CVE-2021-40438 HIGH "$port Apache 2.4.$patch" \
                    "Affected Apache mod_proxy configurations may permit server-side request forgery." \
                    "Upgrade Apache 2.4.$patch to a supported release, at least 2.4.53, and review mod_proxy." \
                    "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
            fi
            if (( 10#$patch == 49 )); then
                add_finding CVE-2021-41773 HIGH "$port Apache 2.4.49" \
                    "Apache 2.4.49 may allow path traversal through vulnerable directory mappings." \
                    "Upgrade Apache 2.4.49 to a supported release, at least 2.4.53." \
                    "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
            fi
            if (( 10#$patch == 49 || 10#$patch == 50 )); then
                add_finding CVE-2021-42013 CRITICAL "$port Apache 2.4.$patch" \
                    "Apache 2.4.49 and 2.4.50 may permit path traversal or remote code execution." \
                    "Upgrade Apache 2.4.$patch to a supported release, at least 2.4.53." \
                    "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"
            fi
        fi
        if [[ "$row" =~ OpenSSH[[:space:]]+([0-9]+)\.([0-9]+)[^[:space:]]* ]]; then
            major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"
            if (( 10#$major < 7 || (10#$major == 7 && 10#$minor < 3) )); then
                add_finding CVE-2016-6210 MEDIUM "$port OpenSSH $major.$minor" \
                    "Older OpenSSH versions may disclose usernames through authentication timing." \
                    "Upgrade OpenSSH $major.$minor to a supported vendor-patched release." \
                    "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2016-6210"
            fi
            if (( 10#$major < 7 || (10#$major == 7 && 10#$minor <= 7) )); then
                add_finding CVE-2018-15473 MEDIUM "$port OpenSSH $major.$minor" \
                    "Affected OpenSSH versions may allow remote username enumeration." \
                    "Upgrade OpenSSH beyond 7.7 or install the distribution's patched package." \
                    "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2018-15473"
            fi
        fi
        if [[ "$row" =~ MySQL[[:space:]]+5\.5\.23([[:space:]]|$) ]]; then
            add_finding CVE-2012-2122 HIGH "$port MySQL 5.5.23" \
                "Affected MySQL builds may allow authentication bypass." \
                "Upgrade MySQL 5.5.23 to a supported release and limit database access." \
                "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2012-2122"
        fi
        if [[ "$row" =~ nginx[[:space:]]+1\.3\.9([[:space:]]|$) ]]; then
            add_finding CVE-2013-2028 HIGH "$port nginx 1.3.9" \
                "Affected nginx versions may contain a chunked-encoding buffer overflow." \
                "Upgrade nginx 1.3.9 to a current supported release." \
                "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2013-2028"
        fi
        if [[ "$row" =~ Samba[[:space:]]+smbd[[:space:]]+3\.0\.20([[:space:]]|$) ]]; then
            add_finding CVE-2007-2447 HIGH "$port Samba 3.0.20" \
                "Affected Samba configurations may allow command execution through username maps." \
                "Upgrade Samba, disable unnecessary username maps, and restrict SMB access." \
                "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2007-2447"
        fi
        if [[ "$row" =~ UnrealIRCd[[:space:]]+3\.2\.8\.1([[:space:]]|$) ]]; then
            add_finding CVE-2010-2075 CRITICAL "$port UnrealIRCd 3.2.8.1" \
                "Compromised UnrealIRCd 3.2.8.1 distributions contain a remote backdoor." \
                "Remove UnrealIRCd 3.2.8.1 and install a current verified release." \
                "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2010-2075"
        fi
        if [[ "$row" =~ Microsoft[[:space:]]+IIS[[:space:]]+httpd[[:space:]]+6\.0([[:space:]]|$) ]]; then
            add_finding CVE-2017-7269 CRITICAL "$port Microsoft IIS 6.0" \
                "IIS 6.0 WebDAV may permit remote code execution." \
                "Migrate IIS 6.0 to a supported platform and disable WebDAV until migration." \
                "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2017-7269"
        fi
        if [[ "$row" =~ Exim[[:space:]]+smtpd[[:space:]]+4\.([0-9]+)([[:space:]]|$) ]]; then
            minor="${BASH_REMATCH[1]}"
            if (( 10#$minor >= 87 && 10#$minor <= 91 )); then
                add_finding CVE-2019-10149 CRITICAL "$port Exim 4.$minor" \
                    "Exim 4.87 through 4.91 may permit remote command execution." \
                    "Upgrade Exim 4.$minor to 4.92 or a newer supported release." \
                    "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2019-10149"
            fi
        fi
        if [[ "$row" =~ Elasticsearch([^0-9]|[[:space:]])+1\.4\.2([[:space:]]|$) ]]; then
            add_finding CVE-2015-1427 HIGH "$port Elasticsearch 1.4.2" \
                "Affected Elasticsearch dynamic scripting may permit remote code execution." \
                "Upgrade Elasticsearch, disable unsafe dynamic scripting, and restrict API access." \
                "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2015-1427"
        fi
        if [[ "$row" =~ OpenSSL[[:space:]]+1\.0\.1([a-f]?)([[:space:]]|$) ]]; then
            version="1.0.1${BASH_REMATCH[1]}"
            add_finding CVE-2014-0160 HIGH "$port OpenSSL $version" \
                "Affected OpenSSL releases may expose process memory through Heartbleed." \
                "Upgrade OpenSSL $version, replace exposed private keys, and reissue affected certificates." \
                "Local version rule" "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
        fi
    done
}

# Positive NSE indicators can provide additional CVEs; exclude negative results.
analyze_nse() {
    local line cve active=0
    while IFS= read -r line; do
        [[ "$line" != *"NOT VULNERABLE"* ]] || continue
        if [[ "$line" == *"VULNERABLE"* ]]; then
            active=1
            if [[ ! "$line" =~ CVE-[0-9]{4}-[0-9]{4,} ]]; then
                add_finding "NSE-${#FINDINGS[@]}" HIGH "Nmap vulnerability script" \
                    "${line#"${line%%[![:space:]]*}"}" \
                    "Investigate the positive NSE finding and apply the affected vendor's current security update." \
                    "Positive NSE script output"
            fi
        fi
        if (( active )) && [[ "$line" =~ (CVE-[0-9]{4}-[0-9]{4,}) ]]; then
            cve="${BASH_REMATCH[1]}"
            add_finding "$cve" HIGH "Nmap vulnerability script" \
                "NSE output references a potential vulnerability requiring confirmation." \
                "Review $cve, validate the affected configuration, and apply the vendor's recommended fix." \
                "Positive NSE script output" "https://nvd.nist.gov/vuln/detail/$cve"
        fi
        [[ ! "$line" =~ ^[0-9]+/(tcp|udp)[[:space:]] ]] || active=0
    done <<< "$SCAN_RESULTS"
}

# Query the NVD CVE 2.0 API with encoded keywords and parse JSON using jq.
query_nvd() {
    local product="$1" version="$2" response record id severity description
    local -a request=(curl -fsS --connect-timeout 10 --max-time 30 --get
        --data-urlencode "keywordSearch=$product $version"
        --data-urlencode "resultsPerPage=5")
    [[ -z "${NVD_API_KEY:-}" ]] || request+=(-H "apiKey: $NVD_API_KEY")
    request+=("https://services.nvd.nist.gov/rest/json/cves/2.0")
    if ! response=$("${request[@]}" 2>/dev/null); then
        NVD_MESSAGES+=("NVD lookup failed for $product $version; local findings remain available.")
        return 0
    fi
    if ! jq -e '.vulnerabilities | type == "array"' >/dev/null 2>&1 <<< "$response"; then
        NVD_MESSAGES+=("NVD returned an invalid response for $product $version.")
        return 0
    fi
    if [[ "$(jq '.vulnerabilities | length' <<< "$response")" == 0 ]]; then
        NVD_MESSAGES+=("NVD found no keyword matches for $product $version.")
        return 0
    fi
    NVD_MESSAGES+=("NVD queried successfully for $product $version.")
    while IFS=$'\t' read -r id severity description; do
        [[ -n "$id" ]] || continue
        add_finding "$id" "$severity" "$product $version" "$description" \
            "Validate $id against the installed $product package and upgrade to a supported patched version." \
            "NIST NVD API keyword search" "https://nvd.nist.gov/vuln/detail/$id"
    done < <(jq -r '.vulnerabilities[] | [
        .cve.id,
        (.cve.metrics.cvssMetricV40[0].cvssData.baseSeverity //
         .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity //
         .cve.metrics.cvssMetricV30[0].cvssData.baseSeverity //
         .cve.metrics.cvssMetricV2[0].baseSeverity // "UNKNOWN"),
        ([.cve.descriptions[]? | select(.lang == "en") | .value][0] //
         "No English description available." | gsub("[\\r\\n\\t]+"; " "))
    ] | @tsv' <<< "$response")
}

# Limit public API calls to two recognized products and respect public rate limits.
run_nvd_queries() {
    local row product version count=0
    local -A queried=()
    if (( USE_NVD == 0 )); then
        NVD_MESSAGES+=("NVD lookups were disabled with -n.")
        return 0
    fi
    for row in "${OPEN_PORTS[@]}"; do
        product=""; version=""
        if [[ "$row" =~ (OpenSSH|vsftpd|ProFTPD|nginx|MySQL|UnrealIRCd)[[:space:]]+([^[:space:]]+) ]]; then
            product="${BASH_REMATCH[1]}"; version="${BASH_REMATCH[2]}"
        elif [[ "$row" =~ Apache[[:space:]]+httpd[[:space:]]+([^[:space:]]+) ]]; then
            product="Apache HTTP Server"; version="${BASH_REMATCH[1]}"
        elif [[ "$row" =~ Exim[[:space:]]+smtpd[[:space:]]+([^[:space:]]+) ]]; then
            product="Exim"; version="${BASH_REMATCH[1]}"
        fi
        [[ -n "$product" && -z "${queried[$product:$version]+found}" ]] || continue
        (( count == 0 )) || sleep "$NVD_DELAY_SECONDS"
        query_nvd "$product" "$version"
        queried["$product:$version"]=1
        (( ++count < 2 )) || break
    done
    (( count > 0 )) || NVD_MESSAGES+=("No service banners contained a recognized product and version.")
}

# Generate a complete report from the single scan and all analysis results.
write_report() {
    local row id severity service description source reference item os index=0
    local critical=0 high=0 medium=0 low=0 unknown=0
    for row in "${FINDINGS[@]}"; do
        IFS=$'\t' read -r id severity _ <<< "$row"
        case "$severity" in
            CRITICAL) ((critical++)) ;; HIGH) ((high++)) ;;
            MEDIUM) ((medium++)) ;; LOW) ((low++)) ;; *) ((unknown++)) ;;
        esac
    done
    {
        echo "================================================================"
        echo "                 NETWORK SECURITY SCAN REPORT"
        echo "================================================================"
        printf 'Target IP Address/Hostname: %s\n' "$TARGET"
        printf 'Report Generated: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf 'Nmap Command: %s\n' "$SCAN_COMMAND"
        printf '\n--- EXECUTIVE SUMMARY ---\n'
        printf 'Open ports: %s\nTotal findings: %s\n' "${#OPEN_PORTS[@]}" "${#FINDINGS[@]}"
        printf 'Severity totals: CRITICAL=%s HIGH=%s MEDIUM=%s LOW=%s UNKNOWN=%s\n' \
            "$critical" "$high" "$medium" "$low" "$unknown"
        if (( USE_OS )); then
            printf '\n--- OPERATING SYSTEM DETECTION ---\n'
            os=$(grep -E '^(OS details:|Running:|Aggressive OS guesses:)' <<< "$SCAN_RESULTS" || true)
            [[ -z "$os" ]] && echo "Operating system could not be determined." || printf '%s\n' "$os"
        fi
        printf '\n--- OPEN PORTS AND DETECTED SERVICES ---\n'
        if (( ${#OPEN_PORTS[@]} == 0 )); then
            echo "No open ports detected."
        else
            printf '%s\n' "${OPEN_PORTS[@]}"
        fi
        printf '\n--- POTENTIAL VULNERABILITIES IDENTIFIED ---\n'
        if (( ${#FINDINGS[@]} == 0 )); then
            echo "No potential vulnerabilities were identified by the available checks."
        else
            for row in "${FINDINGS[@]}"; do
                IFS=$'\t' read -r id severity service description source reference <<< "$row"
                ((index++))
                printf '\nFinding %s: %s\n  Severity: %s\n  Affected service: %s\n' \
                    "$index" "$id" "$severity" "$service"
                printf '  Description: %s\n  Detection source: %s\n  Reference: %s\n' \
                    "$description" "$source" "$reference"
            done
        fi
        printf '\n--- NVD API LOOKUP STATUS ---\n'
        printf '%s\n' "${NVD_MESSAGES[@]}"
        printf '\n--- RECOMMENDATIONS FOR REMEDIATION ---\n'
        if (( ${#RECOMMENDATIONS[@]} == 0 )); then
            echo "Maintain current patching, minimize exposed services, and repeat authorized scans."
        else
            index=0
            for item in "${RECOMMENDATIONS[@]}"; do
                ((index++))
                printf '%s. %s\n' "$index" "$item"
            done
        fi
        printf '\nVersion and NVD keyword matches are potential findings that require verification.\n'
        printf 'This product uses data from the NVD API but is not endorsed or certified by the NVD.\n'
        printf '\n========================= END OF REPORT =========================\n'
    } > "$REPORT_FILE" || {
        printf 'Error: Could not write report file %s.\n' "$REPORT_FILE" >&2
        return 1
    }
}

# Optional HTML enhancement escapes special characters from the text report.
write_html_report() {
    local html_file="${REPORT_FILE%.txt}.html"
    {
        printf '%s\n' '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        printf '%s\n' '<title>Network Security Scan Report</title>'
        printf '%s\n' '<style>body{font:16px system-ui;background:#101827;color:#e5edf8;margin:2rem}pre{white-space:pre-wrap;background:#172235;padding:2rem;border-radius:12px;line-height:1.5}h1{color:#70c8ff}</style>'
        printf '%s\n' '</head><body><h1>Network Security Scan Report</h1><pre>'
        sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$REPORT_FILE"
        printf '%s\n' '</pre></body></html>'
    } > "$html_file" || {
        printf 'Error: Could not create HTML report %s.\n' "$html_file" >&2
        return 1
    }
    printf 'HTML report saved to: %s\n' "$html_file"
}

main() {
    parse_arguments "$@" || return 1
    check_dependencies || return 1
    run_scan || return 1
    analyze_exposure
    analyze_versions
    analyze_nse
    run_nvd_queries
    write_report || return 1
    printf 'Text report saved to: %s\n' "$REPORT_FILE"
    printf 'Potential findings identified: %s\n' "${#FINDINGS[@]}"
    (( USE_HTML == 0 )) || write_html_report || return 1
}

main "$@"