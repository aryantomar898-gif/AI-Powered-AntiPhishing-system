#!/usr/bin/env bash
# ============================================================
#  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
#  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
#  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
#  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
#  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
#  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
#
#  PhishGuard v2.0 - AI-Powered Anti-Phishing & Threat Detection
#  Open Source | MIT License | https://github.com/aryantomar898-gif/AI-Powered-AntiPhishing-system
# ============================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
REPORTS_DIR="${SCRIPT_DIR}/reports"
LOGS_DIR="${SCRIPT_DIR}/logs"
WEB_DIR="${SCRIPT_DIR}/web"
VERSION="2.0.0"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
REPORT_FILE="${REPORTS_DIR}/report_${TIMESTAMP}.json"
LOG_FILE="${LOGS_DIR}/phishguard_${TIMESTAMP}.log"
THREAT_DB="${CONFIG_DIR}/threat_db.json"
WHITELIST="${CONFIG_DIR}/whitelist.txt"
SCAN_INTERVAL=30   # seconds between real-time scans
MAX_RISK_SCORE=100

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_info()  { echo -e "${CYAN}[INFO]${NC}  [$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  [$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} [$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_crit()  { echo -e "${BG_RED}${WHITE}[CRIT]${NC}  [$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    [$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

# ─────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
EOF
    echo -e "${NC}"
    echo -e "    ${WHITE}${BOLD}AI-Powered Anti-Phishing & Threat Detection System v${VERSION}${NC}"
    echo -e "    ${DIM}Open Source | MIT License | Enterprise Grade${NC}"
    echo -e "    ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────
# INITIALIZATION
# ─────────────────────────────────────────────────────────────
init_dirs() {
    mkdir -p "$CONFIG_DIR" "$REPORTS_DIR" "$LOGS_DIR" "$WEB_DIR"
    touch "$LOG_FILE"

    # Initialize threat database if not exists
    if [[ ! -f "$THREAT_DB" ]]; then
        cat > "$THREAT_DB" << 'JSONEOF'
{
  "phishing_domains": [
    "paypa1.com","amazon-security.xyz","microsoft-verify.net",
    "apple-id-support.com","secure-banking-alert.com","login-verify-now.com",
    "account-suspended-verify.com","update-your-account.net","signin-security.com",
    "bankofamerica-alert.com","irs-gov-refund.com","covid-relief-payment.com",
    "netflix-billing-update.com","verify-your-paypal.com"
  ],
  "suspicious_tlds": [".xyz",".tk",".ml",".ga",".cf",".gq",".pw",".top",".click",".loan"],
  "phishing_keywords": [
    "verify your account","your account has been suspended","confirm your identity",
    "unusual activity detected","click here immediately","act now or lose access",
    "your password expires","congratulations you won","update payment info",
    "security alert","limited time offer","verify now","account locked"
  ],
  "malicious_ips": [
    "185.220.101.0/24","45.142.212.0/24","194.165.16.0/24"
  ],
  "suspicious_ports": [1080,3128,8080,8888,9050,4444,5555,6666,7777],
  "c2_indicators": [
    "beacon","heartbeat","checkin","cmd_exec","shell_upload","reverse_shell"
  ]
}
JSONEOF
    fi

    # Initialize whitelist
    if [[ ! -f "$WHITELIST" ]]; then
        cat > "$WHITELIST" << 'EOF'
google.com
microsoft.com
apple.com
amazon.com
github.com
stackoverflow.com
cloudflare.com
akamai.com
fastly.com
EOF
    fi

    # Initialize JSON report
    cat > "$REPORT_FILE" << JSONEOF
{
  "scan_id": "${TIMESTAMP}",
  "tool": "PhishGuard",
  "version": "${VERSION}",
  "start_time": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "os": "$(uname -s)",
  "findings": [],
  "summary": {}
}
JSONEOF
}

# ─────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────
check_deps() {
    log_info "Checking dependencies..."
    local missing=()
    local deps=(curl netstat ss dig nmap python3 jq openssl)

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing optional tools: ${missing[*]}"
        log_warn "Some features may be limited. Install with: sudo apt-get install ${missing[*]}"
    else
        log_ok "All dependencies satisfied."
    fi
}

# ─────────────────────────────────────────────────────────────
# AI THREAT SCORING ENGINE
# ─────────────────────────────────────────────────────────────
ai_score_domain() {
    local domain="$1"
    local score=0
    local reasons=()

    # Feature 1: Domain age heuristic (newly registered = high risk)
    local tld
    tld=$(echo "$domain" | rev | cut -d. -f1 | rev)
    local suspicious_tlds=("xyz" "tk" "ml" "ga" "cf" "gq" "pw" "top" "click" "loan" "win" "stream")
    for stld in "${suspicious_tlds[@]}"; do
        if [[ "$tld" == "$stld" ]]; then
            score=$((score + 20))
            reasons+=("Suspicious TLD: .${tld}")
        fi
    done

    # Feature 2: Domain length (phishing domains tend to be long)
    local domain_len=${#domain}
    if [[ $domain_len -gt 30 ]]; then
        score=$((score + 15))
        reasons+=("Unusually long domain (${domain_len} chars)")
    elif [[ $domain_len -gt 20 ]]; then
        score=$((score + 7))
        reasons+=("Long domain (${domain_len} chars)")
    fi

    # Feature 3: Number count in domain (typosquatting)
    local num_count
    num_count=$(echo "$domain" | tr -cd '0-9' | wc -c)
    if [[ $num_count -gt 2 ]]; then
        score=$((score + 10))
        reasons+=("Multiple digits in domain (${num_count})")
    fi

    # Feature 4: Hyphen count (phishing: paypal-secure-login.com)
    local hyphen_count
    hyphen_count=$(echo "$domain" | tr -cd '-' | wc -c)
    if [[ $hyphen_count -gt 2 ]]; then
        score=$((score + 15))
        reasons+=("Multiple hyphens (${hyphen_count})")
    elif [[ $hyphen_count -gt 0 ]]; then
        score=$((score + 5))
        reasons+=("Domain contains hyphens")
    fi

    # Feature 5: Known brand impersonation
    local brands=("paypal" "amazon" "microsoft" "apple" "google" "facebook" "netflix" "bank" "irs" "gov" "secure" "login" "verify" "account" "update")
    local brand_hits=0
    for brand in "${brands[@]}"; do
        if echo "$domain" | grep -qi "$brand"; then
            brand_hits=$((brand_hits + 1))
        fi
    done
    if [[ $brand_hits -gt 1 ]]; then
        score=$((score + 25))
        reasons+=("Multiple brand keywords: ${brand_hits} matches")
    elif [[ $brand_hits -eq 1 ]]; then
        score=$((score + 10))
        reasons+=("Brand keyword detected")
    fi

    # Feature 6: Subdomain depth
    local subdomain_depth
    subdomain_depth=$(echo "$domain" | tr -cd '.' | wc -c)
    if [[ $subdomain_depth -gt 3 ]]; then
        score=$((score + 15))
        reasons+=("Deep subdomain structure (${subdomain_depth} levels)")
    fi

    # Feature 7: Homoglyph / typosquatting detection
    if echo "$domain" | grep -qP '[0oO]' 2>/dev/null || \
       echo "$domain" | grep -q '[1lI]'; then
        score=$((score + 10))
        reasons+=("Possible homoglyph characters detected")
    fi

    # Cap score
    [[ $score -gt 100 ]] && score=100

    echo "${score}|${reasons[*]}"
}

# ─────────────────────────────────────────────────────────────
# NETWORK CONNECTION SCANNER
# ─────────────────────────────────────────────────────────────
scan_network_connections() {
    log_info "Scanning active network connections..."
    local threats_found=0
    local suspicious_connections=()

    echo -e "\n${BOLD}${WHITE}━━━ NETWORK CONNECTION ANALYSIS ━━━${NC}"

    # Get all established connections
    local connections=""
    if command -v ss &>/dev/null; then
        connections=$(ss -tnp 2>/dev/null | grep ESTAB || true)
    elif command -v netstat &>/dev/null; then
        connections=$(netstat -tnp 2>/dev/null | grep ESTABLISHED || true)
    fi

    if [[ -z "$connections" ]]; then
        log_warn "No active established connections found (may need root)"
        return 0
    fi

    # Suspicious ports scan
    local suspicious_ports=(4444 5555 6666 7777 8888 9001 9050 1337 31337)
    while IFS= read -r conn; do
        local remote_port
        remote_port=$(echo "$conn" | awk '{print $5}' | rev | cut -d: -f1 | rev 2>/dev/null || echo "0")

        for sport in "${suspicious_ports[@]}"; do
            if [[ "$remote_port" == "$sport" ]]; then
                threats_found=$((threats_found + 1))
                suspicious_connections+=("$conn")
                echo -e "  ${RED}[SUSPICIOUS]${NC} Connection to port ${sport}: $conn"
                log_crit "Suspicious port detected: $sport in connection: $conn"
            fi
        done
    done <<< "$connections"

    if [[ $threats_found -eq 0 ]]; then
        echo -e "  ${GREEN}✓${NC} No suspicious port connections detected"
    fi

    echo -e "  ${DIM}Total established connections: $(echo "$connections" | wc -l)${NC}"
    echo ""

    return $threats_found
}

# ─────────────────────────────────────────────────────────────
# DNS ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────
analyze_dns() {
    log_info "Analyzing DNS configuration and queries..."
    echo -e "\n${BOLD}${WHITE}━━━ DNS SECURITY ANALYSIS ━━━${NC}"

    # Check DNS servers
    local dns_servers=()
    if [[ -f /etc/resolv.conf ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "^nameserver"; then
                dns_servers+=("$(echo "$line" | awk '{print $2}')")
            fi
        done < /etc/resolv.conf
    fi

    echo -e "  ${CYAN}Configured DNS Servers:${NC}"
    for dns in "${dns_servers[@]}"; do
        # Check if DNS is a known safe resolver
        local known_safe=("8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1" "9.9.9.9" "208.67.222.222")
        local is_safe=false
        for safe in "${known_safe[@]}"; do
            [[ "$dns" == "$safe" ]] && is_safe=true
        done

        if $is_safe; then
            echo -e "    ${GREEN}✓${NC} $dns (Known safe resolver)"
        else
            echo -e "    ${YELLOW}⚠${NC} $dns (Unknown/custom resolver - verify this is intentional)"
        fi
    done

    # Check for DNS over HTTPS or DoT capability
    echo -e "\n  ${CYAN}DNS Security Features:${NC}"
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "    ${GREEN}✓${NC} systemd-resolved active"
    fi

    # DNSSEC check
    if command -v dig &>/dev/null; then
        local dnssec_result
        dnssec_result=$(dig +dnssec google.com 2>/dev/null | grep -c "RRSIG" || true)
        if [[ $dnssec_result -gt 0 ]]; then
            echo -e "    ${GREEN}✓${NC} DNSSEC validation working"
        else
            echo -e "    ${YELLOW}⚠${NC} DNSSEC not confirmed - consider enabling"
        fi
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────
# EMAIL HEADER ANALYZER
# ─────────────────────────────────────────────────────────────
analyze_email_headers() {
    local email_file="${1:-}"
    echo -e "\n${BOLD}${WHITE}━━━ EMAIL HEADER ANALYSIS ━━━${NC}"

    if [[ -z "$email_file" || ! -f "$email_file" ]]; then
        echo -e "  ${DIM}No email file provided. Use: phishguard.sh --analyze-email <file>${NC}"
        return 0
    fi

    log_info "Analyzing email: $email_file"
    local risk_score=0
    local flags=()

    # SPF check
    if grep -qi "spf=fail" "$email_file" 2>/dev/null; then
        risk_score=$((risk_score + 30))
        flags+=("SPF FAILED - sender domain mismatch")
    elif grep -qi "spf=pass" "$email_file" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} SPF: PASS"
    fi

    # DKIM check
    if grep -qi "dkim=fail" "$email_file" 2>/dev/null; then
        risk_score=$((risk_score + 25))
        flags+=("DKIM FAILED - email may be forged")
    elif grep -qi "dkim=pass" "$email_file" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} DKIM: PASS"
    fi

    # DMARC check
    if grep -qi "dmarc=fail" "$email_file" 2>/dev/null; then
        risk_score=$((risk_score + 25))
        flags+=("DMARC FAILED")
    elif grep -qi "dmarc=pass" "$email_file" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} DMARC: PASS"
    fi

    # Extract and analyze URLs
    local urls
    urls=$(grep -oP 'https?://[^\s<>"]+' "$email_file" 2>/dev/null || true)
    if [[ -n "$urls" ]]; then
        echo -e "  ${CYAN}URLs found in email:${NC}"
        while IFS= read -r url; do
            local domain
            domain=$(echo "$url" | awk -F/ '{print $3}')
            local result
            result=$(ai_score_domain "$domain")
            local score
            score=$(echo "$result" | cut -d'|' -f1)

            if [[ $score -gt 50 ]]; then
                echo -e "    ${RED}[HIGH RISK $score/100]${NC} $url"
                risk_score=$((risk_score + 20))
                flags+=("High-risk URL: $url")
            elif [[ $score -gt 25 ]]; then
                echo -e "    ${YELLOW}[MEDIUM RISK $score/100]${NC} $url"
            else
                echo -e "    ${GREEN}[LOW RISK $score/100]${NC} $url"
            fi
        done <<< "$urls"
    fi

    # Urgency keywords
    local urgency_words=("immediately" "urgent" "expires" "suspended" "verify now" "act now" "limited time" "click here")
    local body_text
    body_text=$(cat "$email_file" 2>/dev/null || true)
    for word in "${urgency_words[@]}"; do
        if echo "$body_text" | grep -qi "$word"; then
            risk_score=$((risk_score + 5))
            flags+=("Urgency language: '$word'")
        fi
    done

    # Display results
    echo -e "\n  ${BOLD}Email Risk Score: $risk_score/100${NC}"
    if [[ ${#flags[@]} -gt 0 ]]; then
        echo -e "  ${RED}Threat Indicators:${NC}"
        for flag in "${flags[@]}"; do
            echo -e "    ${RED}▸${NC} $flag"
        done
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────
# URL / DOMAIN SCANNER
# ─────────────────────────────────────────────────────────────
scan_url() {
    local url="$1"
    local domain
    domain=$(echo "$url" | awk -F/ '{print $3}' | sed 's/:.*//')

    echo -e "\n${BOLD}${WHITE}━━━ URL THREAT ANALYSIS ━━━${NC}"
    echo -e "  ${CYAN}Target:${NC} $url"
    echo -e "  ${CYAN}Domain:${NC} $domain"

    # Check whitelist
    if grep -qi "^${domain}$" "$WHITELIST" 2>/dev/null; then
        echo -e "  ${GREEN}✓ WHITELISTED - Trusted domain${NC}"
        return 0
    fi

    # Check against known phishing DB
    local phish_domains
    phish_domains=$(jq -r '.phishing_domains[]' "$THREAT_DB" 2>/dev/null || true)
    if echo "$phish_domains" | grep -qi "^${domain}$"; then
        echo -e "  ${BG_RED}${WHITE} ⚠ KNOWN PHISHING DOMAIN ⚠ ${NC}"
        log_crit "KNOWN PHISHING DOMAIN DETECTED: $domain"
        return 1
    fi

    # AI scoring
    local result
    result=$(ai_score_domain "$domain")
    local score
    score=$(echo "$result" | cut -d'|' -f1)
    local reasons
    reasons=$(echo "$result" | cut -d'|' -f2-)

    # SSL Certificate check
    echo -e "  ${CYAN}SSL/TLS Analysis:${NC}"
    if command -v openssl &>/dev/null; then
        local ssl_info
        ssl_info=$(echo | timeout 5 openssl s_client -connect "${domain}:443" 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null || echo "SSL_CHECK_FAILED")

        if echo "$ssl_info" | grep -q "SSL_CHECK_FAILED"; then
            echo -e "    ${YELLOW}⚠${NC} Could not verify SSL (no HTTPS or connection failed)"
            score=$((score + 10))
        else
            local expiry
            expiry=$(echo "$ssl_info" | grep "notAfter" | cut -d= -f2 || true)
            echo -e "    ${GREEN}✓${NC} SSL valid - Expires: ${expiry}"

            local issuer
            issuer=$(echo "$ssl_info" | grep "issuer" || true)
            local free_cert_issuers=("Let's Encrypt" "ZeroSSL")
            for issuer_name in "${free_cert_issuers[@]}"; do
                if echo "$issuer" | grep -qi "$issuer_name"; then
                    echo -e "    ${YELLOW}ℹ${NC} Free certificate ($issuer_name) - not necessarily malicious"
                    score=$((score + 5))
                fi
            done
        fi
    fi

    # DNS lookup
    if command -v dig &>/dev/null; then
        echo -e "  ${CYAN}DNS Records:${NC}"
        local a_record
        a_record=$(dig +short A "$domain" 2>/dev/null | head -3 || true)
        if [[ -n "$a_record" ]]; then
            echo -e "    A: $a_record"
        else
            echo -e "    ${YELLOW}⚠${NC} No A record - domain may not exist"
            score=$((score + 15))
        fi

        local mx_record
        mx_record=$(dig +short MX "$domain" 2>/dev/null | head -2 || true)
        if [[ -n "$mx_record" ]]; then
            echo -e "    MX: $mx_record"
        fi
    fi

    # Final verdict
    echo -e "\n  ${BOLD}AI Risk Assessment:${NC}"
    if [[ $score -ge 70 ]]; then
        echo -e "  ${BG_RED}${WHITE}  THREAT LEVEL: CRITICAL ($score/100)  ${NC}"
        echo -e "  ${RED}Recommendation: BLOCK immediately${NC}"
    elif [[ $score -ge 50 ]]; then
        echo -e "  ${BG_YELLOW}  THREAT LEVEL: HIGH ($score/100)  ${NC}"
        echo -e "  ${YELLOW}Recommendation: Exercise extreme caution${NC}"
    elif [[ $score -ge 25 ]]; then
        echo -e "  ${YELLOW}  THREAT LEVEL: MEDIUM ($score/100)  ${NC}"
        echo -e "  ${YELLOW}Recommendation: Verify before proceeding${NC}"
    else
        echo -e "  ${GREEN}  THREAT LEVEL: LOW ($score/100)  ${NC}"
        echo -e "  ${GREEN}Recommendation: Appears safe${NC}"
    fi

    if [[ -n "$reasons" ]]; then
        echo -e "\n  ${CYAN}AI Detection Factors:${NC}"
        IFS='|' read -ra reason_arr <<< "$reasons"
        for reason in "${reason_arr[@]}"; do
            [[ -n "$reason" ]] && echo -e "    ${YELLOW}▸${NC} $reason"
        done
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────
# PROCESS SCANNER (detect suspicious processes)
# ─────────────────────────────────────────────────────────────
scan_processes() {
    log_info "Scanning running processes for threats..."
    echo -e "\n${BOLD}${WHITE}━━━ PROCESS THREAT ANALYSIS ━━━${NC}"

    local suspicious_process_names=("cryptominer" "xmrig" "minerd" "coinhive" "ncat" "nc -e" "bash -i" "python -c" "perl -e" "ruby -e" "wget -q" "curl -s.*sh" "base64 -d")
    local found_threats=0

    # Check running processes
    if command -v ps &>/dev/null; then
        local proc_list
        proc_list=$(ps aux 2>/dev/null || true)

        for suspicious in "${suspicious_process_names[@]}"; do
            local matches
            matches=$(echo "$proc_list" | grep -i "$suspicious" | grep -v "grep" | grep -v "phishguard" || true)
            if [[ -n "$matches" ]]; then
                found_threats=$((found_threats + 1))
                echo -e "  ${RED}[THREAT]${NC} Suspicious process detected: $suspicious"
                echo -e "    ${DIM}$matches${NC}"
                log_crit "Suspicious process: $suspicious"
            fi
        done

        # Check for unusual listening ports
        if command -v ss &>/dev/null; then
            echo -e "  ${CYAN}Listening Services:${NC}"
            local listeners
            listeners=$(ss -tlnp 2>/dev/null | tail -n +2 || true)
            local suspicious_ports=(4444 5555 6666 7777 8888 9001 9050 1337 31337 4545)

            while IFS= read -r listener; do
                local port
                port=$(echo "$listener" | awk '{print $4}' | rev | cut -d: -f1 | rev 2>/dev/null || true)
                for sp in "${suspicious_ports[@]}"; do
                    if [[ "$port" == "$sp" ]]; then
                        found_threats=$((found_threats + 1))
                        echo -e "    ${RED}[BACKDOOR RISK]${NC} Suspicious listener on port $port"
                        log_crit "Suspicious listening port: $port"
                    fi
                done
            done <<< "$listeners"
        fi
    fi

    # Check crontab for malicious persistence
    echo -e "  ${CYAN}Crontab Analysis:${NC}"
    if crontab -l &>/dev/null 2>/dev/null; then
        local cron_content
        cron_content=$(crontab -l 2>/dev/null || true)
        local cron_suspects=("wget" "curl" "bash -i" "nc " "python -c" "/tmp/" "base64")

        local cron_threats=0
        for suspect in "${cron_suspects[@]}"; do
            if echo "$cron_content" | grep -qi "$suspect"; then
                cron_threats=$((cron_threats + 1))
                echo -e "    ${YELLOW}⚠${NC} Suspicious cron entry contains: '$suspect'"
            fi
        done

        if [[ $cron_threats -eq 0 ]]; then
            echo -e "    ${GREEN}✓${NC} Crontab appears clean"
        fi
    else
        echo -e "    ${DIM}No crontab found for current user${NC}"
    fi

    if [[ $found_threats -eq 0 ]]; then
        echo -e "  ${GREEN}✓ No malicious processes detected${NC}"
    else
        echo -e "  ${RED}Total process threats found: $found_threats${NC}"
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────
# BROWSER HISTORY ANALYZER
# ─────────────────────────────────────────────────────────────
analyze_browser_history() {
    echo -e "\n${BOLD}${WHITE}━━━ BROWSER HISTORY PHISHING ANALYSIS ━━━${NC}"
    local checked=false

    # Chrome/Chromium history
    local chrome_paths=(
        "$HOME/.config/google-chrome/Default/History"
        "$HOME/.config/chromium/Default/History"
        "$HOME/Library/Application Support/Google/Chrome/Default/History"
    )

    for chrome_path in "${chrome_paths[@]}"; do
        if [[ -f "$chrome_path" ]]; then
            checked=true
            echo -e "  ${CYAN}Analyzing Chrome history...${NC}"
            # Copy to temp (SQLite is locked while browser is open)
            local tmp_history="/tmp/phishguard_history_$TIMESTAMP"
            cp "$chrome_path" "$tmp_history" 2>/dev/null || continue

            if command -v sqlite3 &>/dev/null; then
                local urls
                urls=$(sqlite3 "$tmp_history" "SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 500;" 2>/dev/null || true)
                local phish_hits=0

                while IFS= read -r url; do
                    local domain
                    domain=$(echo "$url" | awk -F/ '{print $3}' | sed 's/:.*//')
                    [[ -z "$domain" ]] && continue

                    local result
                    result=$(ai_score_domain "$domain")
                    local score
                    score=$(echo "$result" | cut -d'|' -f1)

                    if [[ $score -gt 60 ]]; then
                        phish_hits=$((phish_hits + 1))
                        echo -e "    ${RED}[HIGH RISK]${NC} Visited: $url (Score: $score/100)"
                        log_warn "Risky URL in browser history: $url"
                    fi
                done <<< "$urls"

                rm -f "$tmp_history"

                if [[ $phish_hits -eq 0 ]]; then
                    echo -e "    ${GREEN}✓${NC} No high-risk URLs found in recent history"
                else
                    echo -e "    ${RED}⚠ Found $phish_hits potentially phishing URLs in history${NC}"
                fi
            else
                echo -e "    ${YELLOW}⚠${NC} sqlite3 not installed - cannot analyze browser history"
                rm -f "$tmp_history"
            fi
        fi
    done

    if ! $checked; then
        echo -e "  ${DIM}No browser history files found for current user${NC}"
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────
# HOSTS FILE INTEGRITY CHECK
# ─────────────────────────────────────────────────────────────
check_hosts_file() {
    echo -e "\n${BOLD}${WHITE}━━━ HOSTS FILE INTEGRITY CHECK ━━━${NC}"

    if [[ ! -f /etc/hosts ]]; then
        echo -e "  ${YELLOW}⚠${NC} /etc/hosts not found"
        return
    fi

    local threats=0
    # Look for suspicious redirects of known domains
    local important_domains=("google.com" "microsoft.com" "apple.com" "amazon.com" "paypal.com" "facebook.com" "twitter.com" "github.com")

    echo -e "  ${CYAN}Checking for DNS hijacking in /etc/hosts:${NC}"
    for domain in "${important_domains[@]}"; do
        local entry
        entry=$(grep -i "$domain" /etc/hosts 2>/dev/null | grep -v "^#" | grep -v "^127\." | grep -v "^::1" || true)
        if [[ -n "$entry" ]]; then
            threats=$((threats + 1))
            echo -e "    ${RED}[DNS HIJACK DETECTED]${NC} $domain → $entry"
            log_crit "Hosts file hijacking: $domain → $entry"
        fi
    done

    # Check for unusual entries pointing to non-standard IPs
    local suspicious_entries
    suspicious_entries=$(grep -v "^#" /etc/hosts 2>/dev/null | grep -v "^127\." | grep -v "^::1" | grep -v "^0\.0\.0\.0" | grep -v "localhost" | grep -v "^$" || true)

    if [[ -n "$suspicious_entries" ]]; then
        echo -e "  ${CYAN}Custom hosts entries detected:${NC}"
        echo -e "${DIM}$suspicious_entries${NC}" | while IFS= read -r line; do
            echo -e "    ${YELLOW}ℹ${NC} $line"
        done
    fi

    if [[ $threats -eq 0 ]]; then
        echo -e "    ${GREEN}✓${NC} No DNS hijacking detected in hosts file"
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────
# GENERATE JSON REPORT
# ─────────────────────────────────────────────────────────────
generate_report() {
    local total_threats="${1:-0}"
    local scan_duration="${2:-0}"

    log_info "Generating report: $REPORT_FILE"

    # Build final report
    local report_data
    report_data=$(cat "$REPORT_FILE")

    # Add summary
    local updated_report
    updated_report=$(echo "$report_data" | python3 -c "
import json, sys
data = json.load(sys.stdin)
data['end_time'] = '$(date -Iseconds)'
data['scan_duration_seconds'] = $scan_duration
data['summary'] = {
    'total_threats': $total_threats,
    'scan_completed': True,
    'risk_level': 'CRITICAL' if $total_threats > 5 else 'HIGH' if $total_threats > 2 else 'MEDIUM' if $total_threats > 0 else 'LOW'
}
print(json.dumps(data, indent=2))
" 2>/dev/null || echo "$report_data")

    echo "$updated_report" > "$REPORT_FILE"

    echo -e "\n${BOLD}${WHITE}━━━ SCAN SUMMARY ━━━${NC}"
    echo -e "  ${CYAN}Report saved:${NC}  $REPORT_FILE"
    echo -e "  ${CYAN}Log saved:${NC}     $LOG_FILE"
    echo -e "  ${CYAN}Duration:${NC}      ${scan_duration}s"

    if [[ $total_threats -eq 0 ]]; then
        echo -e "  ${BG_GREEN}${WHITE}  RESULT: CLEAN - No threats detected  ${NC}"
    elif [[ $total_threats -le 2 ]]; then
        echo -e "  ${BG_YELLOW}  RESULT: ${total_threats} threat(s) found - Review recommended  ${NC}"
    else
        echo -e "  ${BG_RED}${WHITE}  RESULT: ${total_threats} THREATS FOUND - IMMEDIATE ACTION REQUIRED  ${NC}"
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────
# AUTO-FIX ENGINE
# ─────────────────────────────────────────────────────────────
apply_fixes() {
    echo -e "\n${BOLD}${WHITE}━━━ AUTO-FIX ENGINE ━━━${NC}"
    echo -e "  ${YELLOW}⚠ Auto-fix will attempt to remediate detected threats${NC}"
    echo -e "  ${YELLOW}⚠ Some fixes require root privileges${NC}\n"

    local fixes_applied=0

    # Fix 1: Update DNS to secure resolvers
    read -rp "  $(echo -e "${CYAN}Apply Fix 1:${NC} Switch to secure DNS (Cloudflare 1.1.1.1)? [y/N]: ")" dns_fix
    if [[ "${dns_fix,,}" == "y" ]]; then
        if [[ $EUID -eq 0 ]]; then
            cp /etc/resolv.conf "/etc/resolv.conf.bak.${TIMESTAMP}"
            echo -e "nameserver 1.1.1.1\nnameserver 1.0.0.1" > /etc/resolv.conf
            echo -e "  ${GREEN}✓${NC} DNS updated to Cloudflare 1.1.1.1 (backup: /etc/resolv.conf.bak.${TIMESTAMP})"
            fixes_applied=$((fixes_applied + 1))
        else
            echo -e "  ${YELLOW}⚠${NC} Requires root. Run: sudo phishguard.sh --fix"
        fi
    fi

    # Fix 2: Flush DNS cache
    read -rp "  $(echo -e "${CYAN}Apply Fix 2:${NC} Flush DNS cache? [y/N]: ")" dns_flush
    if [[ "${dns_flush,,}" == "y" ]]; then
        if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
            systemd-resolve --flush-caches 2>/dev/null && echo -e "  ${GREEN}✓${NC} DNS cache flushed"
        elif command -v nscd &>/dev/null; then
            service nscd restart 2>/dev/null && echo -e "  ${GREEN}✓${NC} NSCD cache flushed"
        else
            echo -e "  ${YELLOW}⚠${NC} No cache flush mechanism found"
        fi
        fixes_applied=$((fixes_applied + 1))
    fi

    # Fix 3: Add malicious domains to hosts block
    read -rp "  $(echo -e "${CYAN}Apply Fix 3:${NC} Block known phishing domains in /etc/hosts? [y/N]: ")" hosts_fix
    if [[ "${hosts_fix,,}" == "y" ]]; then
        if [[ $EUID -eq 0 ]]; then
            local phish_domains
            phish_domains=$(jq -r '.phishing_domains[]' "$THREAT_DB" 2>/dev/null || true)
            echo "" >> /etc/hosts
            echo "# PhishGuard blocks - $(date)" >> /etc/hosts
            while IFS= read -r domain; do
                if ! grep -q "$domain" /etc/hosts; then
                    echo "0.0.0.0 $domain" >> /etc/hosts
                    echo "0.0.0.0 www.$domain" >> /etc/hosts
                fi
            done <<< "$phish_domains"
            echo -e "  ${GREEN}✓${NC} Phishing domains blocked in /etc/hosts"
            fixes_applied=$((fixes_applied + 1))
        else
            echo -e "  ${YELLOW}⚠${NC} Requires root to modify /etc/hosts"
        fi
    fi

    echo -e "\n  ${GREEN}Fixes applied: $fixes_applied${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────
# REAL-TIME MONITOR
# ─────────────────────────────────────────────────────────────
realtime_monitor() {
    echo -e "\n${BOLD}${WHITE}━━━ REAL-TIME THREAT MONITOR ━━━${NC}"
    echo -e "  ${CYAN}Monitoring interval:${NC} every ${SCAN_INTERVAL}s"
    echo -e "  ${CYAN}Press Ctrl+C to stop${NC}\n"

    local monitor_count=0
    while true; do
        monitor_count=$((monitor_count + 1))
        local ts
        ts=$(date '+%H:%M:%S')
        echo -e "  ${DIM}[${ts}] Scan #${monitor_count} running...${NC}"

        # Quick connection check
        local threats
        threats=$(ss -tnp 2>/dev/null | grep -c "ESTAB" || echo "0")
        echo -e "  ${CYAN}Active connections:${NC} $threats"

        # Quick DNS leak check - try to resolve a canary domain
        if command -v dig &>/dev/null; then
            local dns_response
            dns_response=$(dig +short +time=2 example.com 2>/dev/null | head -1 || true)
            if [[ -n "$dns_response" ]]; then
                echo -e "  ${GREEN}✓${NC} DNS resolving normally ($dns_response)"
            else
                echo -e "  ${YELLOW}⚠${NC} DNS resolution issue detected"
            fi
        fi

        # Check /etc/hosts modification time
        local hosts_mtime
        hosts_mtime=$(stat -c %Y /etc/hosts 2>/dev/null || stat -f %m /etc/hosts 2>/dev/null || echo "0")
        if [[ -n "${LAST_HOSTS_MTIME:-}" && "$hosts_mtime" != "$LAST_HOSTS_MTIME" ]]; then
            echo -e "  ${RED}⚠ ALERT: /etc/hosts was modified!${NC}"
            log_crit "/etc/hosts modification detected during monitoring"
        fi
        LAST_HOSTS_MTIME="$hosts_mtime"

        echo -e "  ${DIM}Next scan in ${SCAN_INTERVAL}s...${NC}\n"
        sleep "$SCAN_INTERVAL"
    done
}

# ─────────────────────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────────────────────
progress_bar() {
    local current=$1
    local total=$2
    local label="${3:-}"
    local width=40
    local filled=$(( (current * width) / total ))
    local empty=$(( width - filled ))
    local bar=""

    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    printf "\r  ${CYAN}[${bar}]${NC} %d/%d %s" "$current" "$total" "$label"
    [[ $current -eq $total ]] && echo ""
}

# ─────────────────────────────────────────────────────────────
# FULL SCAN
# ─────────────────────────────────────────────────────────────
run_full_scan() {
    local start_time=$SECONDS
    local total_threats=0

    show_banner
    echo -e "${BOLD}Starting Full System Scan...${NC}"
    echo -e "${DIM}Scan ID: ${TIMESTAMP} | Host: $(hostname) | User: $(whoami)${NC}\n"

    local steps=6
    local step=0

    step=$((step+1)); progress_bar $step $steps "Checking dependencies"
    check_deps

    step=$((step+1)); progress_bar $step $steps "Analyzing network connections"
    scan_network_connections && true
    local net_threats=$?
    total_threats=$((total_threats + net_threats))

    step=$((step+1)); progress_bar $step $steps "Analyzing DNS"
    analyze_dns

    step=$((step+1)); progress_bar $step $steps "Scanning processes"
    scan_processes

    step=$((step+1)); progress_bar $step $steps "Checking hosts file"
    check_hosts_file

    step=$((step+1)); progress_bar $step $steps "Analyzing browser history"
    analyze_browser_history

    local duration=$(( SECONDS - start_time ))
    generate_report "$total_threats" "$duration"
}

# ─────────────────────────────────────────────────────────────
# CLI MENU
# ─────────────────────────────────────────────────────────────
interactive_menu() {
    show_banner
    while true; do
        echo -e "${BOLD}${WHITE}SELECT OPERATION:${NC}"
        echo -e "  ${CYAN}[1]${NC} Full System Scan"
        echo -e "  ${CYAN}[2]${NC} Scan URL / Domain"
        echo -e "  ${CYAN}[3]${NC} Analyze Email Headers"
        echo -e "  ${CYAN}[4]${NC} Real-time Monitor Mode"
        echo -e "  ${CYAN}[5]${NC} Network Connection Scan"
        echo -e "  ${CYAN}[6]${NC} Process & Persistence Scan"
        echo -e "  ${CYAN}[7]${NC} Apply Auto-Fixes"
        echo -e "  ${CYAN}[8]${NC} Start Web Dashboard"
        echo -e "  ${CYAN}[9]${NC} View Last Report"
        echo -e "  ${RED}[0]${NC} Exit"
        echo ""
        read -rp "$(echo -e "  ${BOLD}PhishGuard> ${NC}")" choice

        case "$choice" in
            1) run_full_scan ;;
            2)
                read -rp "  Enter URL or domain to scan: " target_url
                [[ -n "$target_url" ]] && scan_url "$target_url"
                ;;
            3)
                read -rp "  Enter path to email file (.eml): " email_path
                analyze_email_headers "$email_path"
                ;;
            4) realtime_monitor ;;
            5) scan_network_connections ;;
            6) scan_processes ;;
            7) apply_fixes ;;
            8) start_web_dashboard ;;
            9)
                local last_report
                last_report=$(ls -t "${REPORTS_DIR}"/report_*.json 2>/dev/null | head -1 || true)
                if [[ -n "$last_report" ]]; then
                    echo -e "\n${BOLD}Last Report:${NC} $last_report"
                    if command -v jq &>/dev/null; then
                        jq . "$last_report"
                    else
                        cat "$last_report"
                    fi
                else
                    echo -e "  ${YELLOW}No reports found. Run a scan first.${NC}"
                fi
                ;;
            0) echo -e "\n${GREEN}Goodbye. Stay safe!${NC}\n"; exit 0 ;;
            *) echo -e "  ${RED}Invalid option.${NC}" ;;
        esac
        echo ""
        read -rp "  Press Enter to continue..."
        show_banner
    done
}

# ─────────────────────────────────────────────────────────────
# WEB DASHBOARD LAUNCHER
# ─────────────────────────────────────────────────────────────
start_web_dashboard() {
    local port=8745
    echo -e "\n${CYAN}Starting PhishGuard Web Dashboard on port ${port}...${NC}"
    echo -e "${DIM}Open: http://localhost:${port}${NC}\n"

    if command -v python3 &>/dev/null; then
        # Symlink reports to web dir
        ln -sf "$REPORTS_DIR" "${WEB_DIR}/reports" 2>/dev/null || true
        cd "$WEB_DIR"
        python3 -m http.server "$port" --bind 127.0.0.1 &
        local web_pid=$!
        echo -e "${GREEN}✓ Dashboard running (PID: $web_pid)${NC}"
        echo -e "${YELLOW}Press Enter to stop the dashboard...${NC}"
        read -r
        kill "$web_pid" 2>/dev/null || true
        echo -e "${GREEN}Dashboard stopped.${NC}"
    else
        echo -e "${RED}Python3 not found. Cannot start web server.${NC}"
    fi
}

# ─────────────────────────────────────────────────────────────
# ARGUMENT PARSING & ENTRY POINT
# ─────────────────────────────────────────────────────────────
main() {
    init_dirs

    case "${1:-}" in
        --scan|-s)          run_full_scan ;;
        --url|-u)           scan_url "${2:-}" ;;
        --email|-e)         analyze_email_headers "${2:-}" ;;
        --monitor|-m)       show_banner; realtime_monitor ;;
        --fix|-f)           apply_fixes ;;
        --network|-n)       show_banner; scan_network_connections ;;
        --process|-p)       show_banner; scan_processes ;;
        --web|-w)           start_web_dashboard ;;
        --version|-v)       echo "PhishGuard v${VERSION}" ;;
        --help|-h)
            echo ""
            echo -e "${BOLD}PhishGuard v${VERSION} - Usage${NC}"
            echo ""
            echo "  phishguard.sh [OPTION]"
            echo ""
            echo "  (no args)          Interactive CLI menu"
            echo "  --scan, -s         Run full system scan"
            echo "  --url, -u <url>    Scan specific URL/domain"
            echo "  --email, -e <file> Analyze email headers"
            echo "  --monitor, -m      Start real-time monitor"
            echo "  --fix, -f          Apply auto-fixes"
            echo "  --network, -n      Scan network connections"
            echo "  --process, -p      Scan running processes"
            echo "  --web, -w          Start web dashboard"
            echo "  --version, -v      Show version"
            echo "  --help, -h         Show this help"
            echo ""
            ;;
        "")                 interactive_menu ;;
        *)
            echo -e "${RED}Unknown option: ${1}${NC}"
            echo "Use --help for usage."
            exit 1
            ;;
    esac
}

main "$@"
