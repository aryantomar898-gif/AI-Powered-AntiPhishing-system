# 🛡️ PhishGuard v2.0 — AI-Powered Anti-Phishing & Threat Detection

> **Open Source | MIT License | Enterprise-Grade | Real-time Protection**

PhishGuard is a comprehensive **shell-based anti-phishing and threat detection system** for IT teams, featuring an AI scoring engine, real-time monitoring, a terminal CLI, and a beautiful web dashboard — all in a single open-source package.

---

## 📦 Project Structure

```
PhishGuard/
├── phishguard.sh          # Main CLI script (entry point)
├── web/
│   └── index.html         # Web GUI Dashboard (open in browser)
├── config/
│   ├── threat_db.json     # Known phishing domains & threat indicators
│   └── whitelist.txt      # Trusted domains whitelist
├── reports/               # Auto-generated JSON reports
├── logs/                  # Timestamped log files
└── README.md              # This file
```

---

## 🚀 Quick Start

```bash
# Clone / setup
git clone https://github.com/your-org/phishguard
cd PhishGuard
chmod +x phishguard.sh

# Interactive CLI menu
./phishguard.sh

# Full system scan
./phishguard.sh --scan

# Scan a URL or domain
./phishguard.sh --url paypal-secure-verify.xyz

# Analyze email headers (.eml file)
./phishguard.sh --email suspicious.eml

# Real-time monitoring mode
./phishguard.sh --monitor

# Start web dashboard
./phishguard.sh --web
# Then open http://localhost:8745

# Apply auto-fixes (requires sudo)
sudo ./phishguard.sh --fix
```

---

## 🧠 AI Threat Detection Engine

PhishGuard's scoring engine analyzes domains across **7 ML-inspired feature dimensions**:

| Feature | Description | Max Score |
|---|---|---|
| Suspicious TLD | .xyz, .tk, .ml, .gq etc. | +20 |
| Domain Length | >30 chars = high risk | +18 |
| Digit Density | Typosquatting indicator | +12 |
| Hyphen Count | paypal-secure-login.com | +15 |
| Brand Keywords | "amazon", "paypal", "verify" | +28 |
| Subdomain Depth | login.verify.update.com | +15 |
| Homoglyphs | paypa1, rn→m lookalikes | +10 |

**Risk levels:**
- 🟢 **LOW** (0–24): Safe to proceed
- 🟡 **MEDIUM** (25–49): Verify before proceeding
- 🟠 **HIGH** (50–69): Exercise extreme caution
- 🔴 **CRITICAL** (70–100): BLOCK immediately

---

## 🔍 Detection Capabilities

### Network
- Active connection analysis (suspicious ports: 4444, 5555, 9050, 1337, etc.)
- Listener / backdoor port detection
- DNS server validation
- DNSSEC verification
- DNS leak detection

### System
- `/etc/hosts` hijacking detection
- Crontab persistence analysis
- Running process inspection (miners, netcat, reverse shells)
- Browser history phishing URL scan (Chrome/Chromium)

### Email
- SPF / DKIM / DMARC header verification
- URL extraction and AI scoring
- Urgency language detection
- Sender impersonation patterns

### SSL/TLS
- Certificate validity check
- Free CA detection (Let's Encrypt, ZeroSSL)
- HTTPS enforcement check

---

## 🖥️ Dual Interface

### CLI (Terminal)
```
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ...

  SELECT OPERATION:
  [1] Full System Scan
  [2] Scan URL / Domain
  [3] Analyze Email Headers
  [4] Real-time Monitor Mode
  [5] Network Connection Scan
  [6] Process & Persistence Scan
  [7] Apply Auto-Fixes
  [8] Start Web Dashboard
  [9] View Last Report
  [0] Exit

  PhishGuard> _
```

### Web GUI (`web/index.html`)
- Real-time threat feed
- AI URL scanner widget
- 24-hour activity chart
- Network connection table
- Security checks panel
- Live terminal console
- One-click JSON report export

---

## 🔧 Auto-Fix Engine

With `sudo ./phishguard.sh --fix`, PhishGuard can:

1. **Switch DNS** to secure Cloudflare resolvers (1.1.1.1 / 1.0.0.1) — with backup
2. **Flush DNS cache** (systemd-resolved / nscd)
3. **Block phishing domains** in `/etc/hosts` (0.0.0.0 redirect)

---

## 📊 Report Format (JSON)

```json
{
  "scan_id": "20240101_120000",
  "tool": "PhishGuard",
  "version": "2.0.0",
  "start_time": "2024-01-01T12:00:00+00:00",
  "hostname": "workstation-01",
  "findings": [
    {
      "type": "phishing_domain",
      "domain": "paypal-secure-verify.xyz",
      "score": 83,
      "level": "critical",
      "indicators": ["Suspicious TLD", "Brand keywords", "Multiple hyphens"]
    }
  ],
  "summary": {
    "total_threats": 3,
    "risk_level": "HIGH",
    "scan_duration_seconds": 12
  }
}
```

---

## 🛠️ Requirements

| Tool | Required | Purpose |
|---|---|---|
| bash ≥4.0 | ✅ Required | Core runtime |
| python3 | ✅ Required | Report generation + web server |
| curl | Recommended | URL verification |
| dig / nslookup | Recommended | DNS analysis |
| openssl | Recommended | SSL/TLS checks |
| ss / netstat | Recommended | Network scanning |
| jq | Optional | JSON pretty-print |
| sqlite3 | Optional | Browser history scan |
| nmap | Optional | Port scanning |

Install all on Debian/Ubuntu:
```bash
sudo apt-get install curl dnsutils openssl iproute2 jq sqlite3 nmap python3
```

---

## 🔒 Privacy & Permissions

- **No data leaves your machine** — all analysis is local
- Root (`sudo`) only required for DNS changes and hosts file modifications
- Browser history access requires local file permissions only
- No telemetry, no API calls to external services

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/add-yara-rules`
3. Add threat signatures to `config/threat_db.json`
4. Test with: `./phishguard.sh --scan`
5. Submit a pull request

**Ideas for contributions:**
- YARA rule integration
- VirusTotal API lookup module
- Slack/Teams alert integration
- systemd service file for persistent monitoring
- Email alert on critical detection
- pfSense / firewall rule auto-generation

---

## 📜 License

MIT License — Free for personal and commercial use.

---

## ⚠️ Disclaimer

PhishGuard is a defense tool for authorized use on systems you own or have permission to scan. Do not use against systems without explicit authorization.

---

*Built for IT Security Teams | Open Source Forever | No tracking, no cloud, no BS*
