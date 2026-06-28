PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  destination_ip TEXT,
  attack_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INTEGER NOT NULL,
  packet_count INTEGER NOT NULL,
  time_window INTEGER NOT NULL,
  threat_score REAL NOT NULL,
  country_code TEXT,
  isp TEXT,
  asn TEXT,
  auto_blocked INTEGER DEFAULT 0,
  resolved INTEGER DEFAULT 0,
  notes TEXT,
  raw_data TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT UNIQUE,
  blocked_at TEXT NOT NULL,
  blocked_by TEXT DEFAULT 'AUTO',
  reason TEXT,
  unblocked_at TEXT,
  is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ip_reputation (
  ip_address TEXT PRIMARY KEY,
  abuse_score INTEGER,
  country_code TEXT,
  isp TEXT,
  asn TEXT,
  usage_type TEXT,
  last_checked TEXT NOT NULL,
  raw_response TEXT
);

CREATE TABLE IF NOT EXISTS traffic_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  packets_per_second REAL NOT NULL,
  bytes_per_second REAL NOT NULL,
  tcp_count INTEGER NOT NULL,
  udp_count INTEGER NOT NULL,
  icmp_count INTEGER NOT NULL,
  unique_sources INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip_address ON blocked_ips(ip_address);

