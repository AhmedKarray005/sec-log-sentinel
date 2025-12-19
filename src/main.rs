use chrono::{DateTime, Duration as ChronoDuration, Utc};
use clap::{Parser, Subcommand};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

// ===== ANSI COLORS =====
const C_RESET: &str = "\x1b[0m";
const C_INFO: &str = "\x1b[36m";      // Cyan
const C_WARN: &str = "\x1b[33m";      // Yellow
const C_ERROR: &str = "\x1b[31;1m";   // Bright Red
const C_ALERT: &str = "\x1b[31;1m";   // Bright Red
const C_OK: &str = "\x1b[32m";        // Green
const C_HEADING: &str = "\x1b[35;1m"; // Magenta bold
const C_DIM: &str = "\x1b[2m";        // Dim/gray

/// Security Log Sentinel
///
/// Defensive tool to analyze and monitor authentication logs,
/// detect suspicious patterns (brute force, password spraying, etc.)
#[derive(Parser, Debug)]
#[command(name = "sec_log_sentinel")]
#[command(about = "Analyze authentication logs and detect suspicious activity")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// One-shot analysis of a log file
    Analyze {
        /// Path to the log file
        file: PathBuf,
    },

    /// Live monitoring: follow the log file as it grows
    Monitor {
        /// Path to the log file
        file: PathBuf,
    },
}

/// Type of event found in a log line
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventType {
    LoginSuccess,
    LoginFail,
    Other,
}

/// Parsed log entry
#[derive(Debug, Clone)]
struct LogEvent {
    timestamp: DateTime<Utc>,
    #[allow(dead_code)]
    level: String,
    event_type: EventType,
    user: Option<String>,
    ip: Option<String>,
    #[allow(dead_code)]
    raw: String,
}
/// One failed attempt record (for time-window detection)
#[derive(Clone)]
struct FailRecord {
    ts: DateTime<Utc>,
    #[allow(dead_code)]
    user: Option<String>,
    #[allow(dead_code)]
    ip: Option<String>,
}

/// Analyzer keeping state while we feed LogEvent objects into it
struct Analyzer {
    total_events: u64,
    login_success: u64,
    login_fail: u64,

    // Global stats
    fails_per_user: HashMap<String, u64>,
    fails_per_ip: HashMap<String, u64>,

    // For brute-force detection (per IP, with time window)
    recent_fails_per_ip: HashMap<String, VecDeque<FailRecord>>,

    // For password spraying (one IP → many users)
    users_per_ip: HashMap<String, HashSet<String>>,

    // For account takeover (one user → many IPs)
    ips_per_user: HashMap<String, HashSet<String>>,
}

impl Analyzer {
    fn new() -> Self {
        Self {
            total_events: 0,
            login_success: 0,
            login_fail: 0,
            fails_per_user: HashMap::new(),
            fails_per_ip: HashMap::new(),
            recent_fails_per_ip: HashMap::new(),
            users_per_ip: HashMap::new(),
            ips_per_user: HashMap::new(),
        }
    }

    fn feed(&mut self, ev: &LogEvent) {
        self.total_events += 1;

        match ev.event_type {
            EventType::LoginSuccess => {
                self.login_success += 1;
            }
            EventType::LoginFail => {
                self.login_fail += 1;

                let user = ev.user.clone().unwrap_or_else(|| "<unknown>".to_string());
                let ip = ev.ip.clone().unwrap_or_else(|| "<no-ip>".to_string());

                // Global counters
                *self.fails_per_user.entry(user.clone()).or_insert(0) += 1;
                *self.fails_per_ip.entry(ip.clone()).or_insert(0) += 1;

                // Keep recent fails per IP (for brute-force detection)
                let rec = FailRecord {
                    ts: ev.timestamp,
                    user: ev.user.clone(),
                    ip: ev.ip.clone(),
                };
                self.recent_fails_per_ip
                    .entry(ip.clone())
                    .or_insert_with(VecDeque::new)
                    .push_back(rec);

                // Password spraying: one IP → many users
                self.users_per_ip
                    .entry(ip.clone())
                    .or_insert_with(HashSet::new)
                    .insert(user.clone());

                // Account takeover: one user → many IPs
                self.ips_per_user
                    .entry(user.clone())
                    .or_insert_with(HashSet::new)
                    .insert(ip.clone());
            }
            EventType::Other => {}
        }
    }

    fn print_summary(&self) {
        println!();
        println!("{C_HEADING}==================== SUMMARY ===================={C_RESET}");
        println!("Total events      : {}", self.total_events);
        println!(
            "LOGIN_SUCCESS     : {C_OK}{}{C_RESET}",
            self.login_success
        );
        println!(
            "LOGIN_FAIL        : {C_WARN}{}{C_RESET}",
            self.login_fail
        );
        println!("{C_HEADING}================================================={C_RESET}");

        // Top 5 users with most failed logins
        if !self.fails_per_user.is_empty() {
            println!("{C_HEADING}Top users by failed logins:{C_RESET}");
            let mut items: Vec<(&String, &u64)> = self.fails_per_user.iter().collect();
            items.sort_by(|a, b| b.1.cmp(a.1)); // desc by count
            for (i, (user, count)) in items.into_iter().take(5).enumerate() {
                println!("  {}. {} -> {} failed attempts", i + 1, user, count);
            }
        }

        // Top 5 IPs with most failed logins
        if !self.fails_per_ip.is_empty() {
            println!();
            println!("{C_HEADING}Top IPs by failed logins:{C_RESET}");
            let mut items: Vec<(&String, &u64)> = self.fails_per_ip.iter().collect();
            items.sort_by(|a, b| b.1.cmp(a.1));
            for (i, (ip, count)) in items.into_iter().take(5).enumerate() {
                println!("  {}. {} -> {} failed attempts", i + 1, ip, count);
            }
        }

        println!("{C_HEADING}================================================={C_RESET}");
        println!("{C_HEADING}RISK ASSESSMENT (per user & IP):{C_RESET}");

        // Simple static thresholds for batch summary
        const THRESH_USER: u64 = 3;
        const THRESH_IP: u64 = 3;

        let mut any = false;

        for (user, fails) in &self.fails_per_user {
            if *fails >= THRESH_USER {
                any = true;
                println!(
                    "{C_WARN}Suspicious user (>=3 failed logins):{C_RESET} {user} -> {fails}"
                );
            }
        }

        for (ip, fails) in &self.fails_per_ip {
            if *fails >= THRESH_IP {
                any = true;
                println!(
                    "{C_WARN}Suspicious ip (>=3 failed logins):{C_RESET} {ip} -> {fails}"
                );
            }
        }

        if !any {
            println!("{C_OK}No high-risk user/IP detected with static thresholds.{C_RESET}");
        }

        println!("{C_HEADING}================================================={C_RESET}");
        println!(
            "{C_DIM}(Next steps: real-time monitor mode using the same logic){C_RESET}"
        );
    }
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Analyze { file } => run_analyze(&file),
        Command::Monitor { file } => run_monitor(&file),
    };

    if let Err(e) = result {
        eprintln!("{C_ERROR}[ERROR]{C_RESET} {}", e);
        std::process::exit(1);
    }
}

/// Batch analysis: read the file once, analyze all lines.
fn run_analyze(path: &PathBuf) -> Result<(), String> {
    println!(
        "{C_INFO}[INFO]{C_RESET} Running batch analysis on {:?}",
        path
    );

    let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let reader = BufReader::new(file);

    let mut analyzer = Analyzer::new();
    let mut parsed = 0usize;
    let mut errors = 0usize;

    for (line_no, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Failed to read line {}: {}", line_no + 1, e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match parse_log_line(trimmed) {
            Ok(ev) => {
                analyzer.feed(&ev);
                parsed += 1;
            }
            Err(err) => {
                errors += 1;
                eprintln!(
                    "{C_WARN}[WARN]{C_RESET} Line {}: {} -> \"{}\"",
                    line_no + 1,
                    err,
                    trimmed
                );
            }
        }
    }

    println!(
        "{C_INFO}[INFO]{C_RESET} Parsed {} events ({} errors)",
        parsed, errors
    );
    analyzer.print_summary();

    Ok(())
}

/// Live monitoring: follow the log file as it grows.
fn run_monitor(path: &PathBuf) -> Result<(), String> {
    println!("{C_INFO}[INFO]{C_RESET} Live monitoring {:?}", path);

    // Open file once to get initial length and to keep a handle
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut analyzer = Analyzer::new();

    // Start reading from current end of file (we only want NEW lines)
    let mut last_pos = file
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("Failed to seek: {}", e))?;

    println!(
        "{C_INFO}[INFO]{C_RESET} Waiting for new log lines (Ctrl+C to stop)..."
    );

    loop {
        // Check file size
        let metadata =
            std::fs::metadata(path).map_err(|e| format!("Failed to stat file: {}", e))?;
        let file_len = metadata.len();

        if file_len < last_pos {
            // File was truncated/rotated
            println!(
                "{C_INFO}[INFO]{C_RESET} Log file truncated. Resetting offset to 0."
            );
            last_pos = 0;
        }

        if file_len > last_pos {
            // There is new data
            let mut new_file =
                File::open(path).map_err(|e| format!("Failed to reopen file: {}", e))?;
            new_file
                .seek(SeekFrom::Start(last_pos))
                .map_err(|e| format!("Failed to seek: {}", e))?;

            let mut reader = BufReader::new(new_file);
            let mut buf: Vec<u8> = Vec::new();
            let mut bytes_read: u64 = 0;

            loop {
                buf.clear();
                // read_until never fails on UTF-8; it works on raw bytes
                let n = reader
                    .read_until(b'\n', &mut buf)
                    .map_err(|e| format!("Failed to read line: {}", e))?;
                if n == 0 {
                    break;
                }
                bytes_read += n as u64;

                // Strip trailing \r and \n
                while buf
                    .last()
                    .map_or(false, |b| *b == b'\n' || *b == b'\r')
                {
                    buf.pop();
                }
                if buf.is_empty() {
                    continue;
                }

                // Convert to UTF-8 lossy (invalid bytes become � instead of error)
                let line = String::from_utf8_lossy(&buf);
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match parse_log_line(trimmed) {
                    Ok(ev) => {
                        println!(
                            "{C_DIM}[EVENT]{C_RESET} {:?} user={:?} ip={:?}",
                            ev.event_type, ev.user, ev.ip
                        );
                        analyzer.feed(&ev);
                        check_realtime_alerts(&mut analyzer, &ev);
                    }
                    Err(err) => {
                        eprintln!(
                            "{C_WARN}[WARN]{C_RESET} Could not parse line: {} -> \"{}\"",
                            err, trimmed
                        );
                    }
                }
            }

            last_pos += bytes_read;
        }

        // Sleep a bit to avoid busy loop
        thread::sleep(Duration::from_millis(500));
    }
}


/// Real-time alerting logic (monitor mode).
fn check_realtime_alerts(an: &mut Analyzer, ev: &LogEvent) {
    if ev.event_type != EventType::LoginFail {
        return;
    }

    let ip = ev.ip.clone().unwrap_or_else(|| "<no-ip>".into());
    let user = ev.user.clone().unwrap_or_else(|| "<unknown>".into());

    let now = ev.timestamp;
    let window = ChronoDuration::seconds(30); // time window for brute-force

    // === BRUTE FORCE DETECTION (many failures from same IP in 30s) ===
    if let Some(queue) = an.recent_fails_per_ip.get_mut(&ip) {
        // Remove old entries out of the window
        while let Some(front) = queue.front() {
            if now - front.ts > window {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= 5 {
            println!(
                "{C_ALERT}[ALERT]{C_RESET} Possible BRUTE-FORCE from ip={} ({} failed logins in 30s)",
                ip,
                queue.len()
            );
        }
    }

    // === PASSWORD SPRAYING (one IP touches many users) ===
    if let Some(users) = an.users_per_ip.get(&ip) {
        if users.len() >= 5 {
            println!(
                "{C_ALERT}[ALERT]{C_RESET} Possible PASSWORD SPRAYING from ip={} ({} distinct users targeted)",
                ip,
                users.len()
            );
        }
    }

    // === ACCOUNT TAKEOVER (one user attacked from many IPs) ===
    if let Some(ips) = an.ips_per_user.get(&user) {
        if ips.len() >= 5 {
            println!(
                "{C_ALERT}[ALERT]{C_RESET} Possible ACCOUNT TAKEOVER targeting user={} ({} distinct attacker IPs)",
                user,
                ips.len()
            );
        }
    }
}

/// Parse one log line into a LogEvent.
///
/// Example:
/// 2025-12-04T10:15:30Z INFO  LOGIN_SUCCESS user=alice ip=192.168.1.10

fn parse_log_line(line: &str) -> Result<LogEvent, String> {
    let mut parts = line.split_whitespace();

    let ts_raw = parts
        .next()
        .ok_or_else(|| "Missing timestamp field".to_string())?;
    let ts_str = ts_raw.trim_start_matches('\u{feff}');

    let level = parts
        .next()
        .ok_or_else(|| "Missing level field".to_string())?;
    let event_type_str = parts
        .next()
        .ok_or_else(|| "Missing event type field".to_string())?;

    // Parse timestamp as RFC3339/ISO8601, e.g. 2025-12-04T10:15:30Z
    let ts = chrono::DateTime::parse_from_rfc3339(ts_str)
        .map_err(|e| format!("Invalid timestamp '{}': {}", ts_str, e))?
        .with_timezone(&Utc);

    let event_type = match event_type_str {
        "LOGIN_SUCCESS" => EventType::LoginSuccess,
        "LOGIN_FAIL" => EventType::LoginFail,
        _ => EventType::Other,
    };

    // Remaining tokens are key=value
    let mut user: Option<String> = None;
    let mut ip: Option<String> = None;

    for token in parts {
        if let Some(eq_pos) = token.find('=') {
            let key = &token[..eq_pos];
            let value = &token[eq_pos + 1..];

            match key {
                "user" => user = Some(value.to_string()),
                "ip" => ip = Some(value.to_string()),
                _ => {
                    // ignore other keys (reason, etc.)
                }
            }
        }
    }

    Ok(LogEvent {
        timestamp: ts,
        level: level.to_string(),
        event_type,
        user,
        ip,
        raw: line.to_string(),
    })
}
