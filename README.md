# Security Log Sentinel
Advanced defensive cyber tool written in Rust to analyze and monitor authentication logs in real time.  
It detects multiple attack patterns such as brute-force, password spraying, and account takeover attempts, all with color-coded alerts for fast triage.

---

## 1. Authors
- **Ahmed Karray — Group CDOF3**

---

## 2. Project Overview
Security Log Sentinel is a Rust-based defensive cybersecurity tool capable of:

- Parsing authentication logs  
- Detecting suspicious or malicious login behaviour  
- Running in **batch analysis** mode  
- Running in **real-time monitoring** mode  
- Displaying color-coded alerts  
- Detecting patterns similar to SIEM and IDS tools  

This project was built for the “Cybersecurity / Offensive & Defensive Tools” module.

---

## 3. Features

### ✔ Batch log analysis (`analyze`)
Reads a complete log file and generates a detailed security report:

- Number of successful logins  
- Number of failed logins  
- Suspicious users  
- Suspicious IPs  
- Top failed users and IPs  
- Color-coded output  

---

### ✔ Real-time log monitoring (`monitor`)
Works like `tail -f`, but with **live detection of attacks**:

- Detects new log lines instantly  
- Parses + analyses each new line  
- Prints real-time alerts  
- Displays events in gray, warnings in yellow, alerts in red  

Realtime detection includes:
- **Brute-force attacks**  
- **Password spraying**  
- **Account takeover attempts**  

---

### ✔ Attack detection rules

| Attack Type | Trigger Condition |
|-------------|------------------|
| **Brute-force** | ≥ 5 failed logins from same IP within 30 seconds |
| **Password spraying** | One IP failing on ≥ 5 distinct users |
| **Account takeover** | One user failing from ≥ 5 distinct IPs |

Thresholds are easily editable.

---

## 4. Expected Log Format

Each log line must follow:

TIMESTAMP LEVEL EVENT_TYPE key=value key=value ...

makefile
Copy code

Example:

2025-12-04T10:15:30Z INFO LOGIN_SUCCESS user=alice ip=192.168.1.10
2025-12-04T10:16:00Z WARN LOGIN_FAIL user=alice ip=203.0.113.5 reason=wrong_password

yaml
Copy code

**Required:**
- Timestamp = RFC3339  
- `LOGIN_SUCCESS` or `LOGIN_FAIL`  
- Recommended: `user=`, `ip=`  

---

## 5. Installing & Running

### Build
cargo build

makefile
Copy code

Optional:
cargo fmt
cargo clippy

yaml
Copy code

---

## 6. Usage Examples

### A) Batch analysis
cargo run -- analyze sample_logs.txt

lua
Copy code

Example output:
[INFO] Parsed 8 events (0 errors)
LOGIN_SUCCESS: 2
LOGIN_FAIL: 6
Suspicious user: alice
Suspicious IP: 203.0.113.5

yaml
Copy code

---

### B) Real-time monitoring
Terminal 1:
cargo run -- monitor live_logs.txt

scss
Copy code

Terminal 2 (simulate attacks):
echo "2025-12-04T10:16:00Z WARN LOGIN_FAIL user=alice ip=203.0.113.5" >> live_logs.txt

lua
Copy code

Example monitor output:
[EVENT] LoginFail user=alice ip=203.0.113.5
[ALERT] Possible BRUTE-FORCE from ip=203.0.113.5 (5 failed logins in 30s)

yaml
Copy code

---

## 7. Internal Architecture

### Components:
- **Cli / Command** → CLI parser via `clap`
- **LogEvent** → Parsed log structure
- **Analyzer** →  
  - Counts events  
  - Tracks user/IP failures  
  - Stores sliding windows  
  - Tracks users per IP and IPs per user  
- **run_analyze()** → Batch mode  
- **run_monitor()** → Real-time mode  
- **check_realtime_alerts()** → Attack detection engine  

---

## 8. Limitations

Current limitations:
- Only supports simplified log format  
- No JSON or syslog parser  
- Static thresholds  
- No dashboards  
- No export functionality  

Future improvements:
- Configurable thresholds  
- Multiple log formats  
- GUI or web interface  
- API for external integrations  

---

## 9. Responsible Use
This tool is strictly for:
- Education  
- SOC / Blue team learning  
- Authorized environments  

Do **NOT** use this tool to analyze or monitor logs without explicit permission.  
Unauthorized monitoring is illegal.

---

## 10. License
Educational project license — for coursework and demonstration purposes.
