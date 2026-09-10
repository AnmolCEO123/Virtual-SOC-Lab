import { useState } from "react";
import {
  Shield,
  LayoutDashboard,
  Bell,
  LockKeyhole,
  Network,
  Radar,
  Radio,
  Target,
  FileText,
  Search,
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Server,
  Globe,
  Terminal,
  MapPin,
  Hash,
  Database,
  Clock3,
  RefreshCw,
  ShieldAlert,
  ScanSearch,
  Wifi,
} from "lucide-react";

import "./App.css";

/* =========================================================
   STATIC SOC DATA
========================================================= */

const alerts = [
  {
    severity: "HIGH",
    type: "BRUTE_FORCE",
    source: "192.168.56.10",
    description: "Multiple failed login attempts detected",
    time: "Today, 16:42",
  },
  {
    severity: "MEDIUM",
    type: "HTTP_403",
    source: "192.168.56.30",
    description: "Forbidden web resource access detected",
    time: "Today, 16:39",
  },
];

const authEvents = [
  {
    time: "16:42:08",
    event: "LOGIN_FAILURE",
    user: "admin",
    source: "192.168.56.10",
    result: "FAILED",
  },
  {
    time: "16:42:05",
    event: "LOGIN_FAILURE",
    user: "admin",
    source: "192.168.56.10",
    result: "FAILED",
  },
  {
    time: "16:42:02",
    event: "LOGIN_FAILURE",
    user: "admin",
    source: "192.168.56.10",
    result: "FAILED",
  },
  {
    time: "16:41:59",
    event: "LOGIN_FAILURE",
    user: "admin",
    source: "192.168.56.10",
    result: "FAILED",
  },
  {
    time: "16:41:56",
    event: "LOGIN_FAILURE",
    user: "admin",
    source: "192.168.56.10",
    result: "FAILED",
  },
  {
    time: "16:40:21",
    event: "LOGIN_SUCCESS",
    user: "analyst",
    source: "192.168.56.20",
    result: "SUCCESS",
  },
  {
    time: "16:40:18",
    event: "LOGIN_SUCCESS",
    user: "analyst",
    source: "192.168.56.20",
    result: "SUCCESS",
  },
];

const networkActivity = [
  {
    time: "16:43:11",
    event: "TCP_CONNECTION",
    source: "192.168.56.20",
    destination: "192.168.56.1:80",
    protocol: "TCP",
  },
  {
    time: "16:43:07",
    event: "TCP_CONNECTION",
    source: "192.168.56.30",
    destination: "192.168.56.1:8000",
    protocol: "TCP",
  },
  {
    time: "16:43:03",
    event: "DNS_QUERY",
    source: "192.168.56.20",
    destination: "example.com",
    protocol: "DNS",
  },
];

const nmapResults = [
  {
    port: "135/tcp",
    state: "open",
    service: "msrpc",
  },
  {
    port: "445/tcp",
    state: "open",
    service: "microsoft-ds",
  },
  {
    port: "8090/tcp",
    state: "open",
    service: "tcpwrapped",
  },
];

const mitreTechniques = [
  {
    id: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    evidence: "5 failed login attempts from 192.168.56.10",
    severity: "HIGH",
  },
  {
    id: "T1046",
    name: "Network Service Scanning",
    tactic: "Discovery",
    evidence: "Nmap service discovery against authorized lab target",
    severity: "MEDIUM",
  },
  {
    id: "T1071.004",
    name: "DNS",
    tactic: "Command and Control",
    evidence: "DNS query observed in lab network telemetry",
    severity: "LOW",
  },
];

const packetData = [
  {
    packet: "ICMP",
    source: "10.0.3.15",
    destination: "10.0.3.2",
    packets: "20",
    status: "CAPTURED",
  },
  {
    packet: "ICMP Echo Request",
    source: "10.0.3.15",
    destination: "10.0.3.2",
    packets: "10",
    status: "CAPTURED",
  },
  {
    packet: "ICMP Echo Reply",
    source: "10.0.3.2",
    destination: "10.0.3.15",
    packets: "10",
    status: "CAPTURED",
  },
];

/* =========================================================
   NAVIGATION
========================================================= */

const navItems = [
  {
    group: "MONITORING",
    items: [
      {
        id: "overview",
        label: "Overview",
        icon: LayoutDashboard,
      },
      {
        id: "alerts",
        label: "Security Alerts",
        icon: Bell,
        badge: 2,
      },
      {
        id: "authentication",
        label: "Authentication",
        icon: LockKeyhole,
      },
      {
        id: "network",
        label: "Network Activity",
        icon: Network,
      },
    ],
  },
  {
    group: "INVESTIGATION",
    items: [
      {
        id: "recon",
        label: "Reconnaissance",
        icon: Radar,
      },
      {
        id: "packets",
        label: "Packet Analysis",
        icon: Radio,
      },
      {
        id: "mitre",
        label: "MITRE ATT&CK",
        icon: Target,
      },
      {
        id: "report",
        label: "Investigation Report",
        icon: FileText,
      },
    ],
  },
];

const pageTitles = {
  overview: "Overview",
  alerts: "Security Alerts",
  authentication: "Authentication",
  network: "Network Activity",
  recon: "Reconnaissance",
  packets: "Packet Analysis",
  mitre: "MITRE ATT&CK",
  report: "Investigation Report",
};

/* =========================================================
   HELPERS
========================================================= */

function getTime() {
  return new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function riskClass(verdict = "") {
  const value = verdict.toLowerCase();

  if (value.includes("high")) return "risk-high";
  if (value.includes("medium")) return "risk-medium";
  if (value.includes("low")) return "risk-low";

  return "risk-low";
}

/* =========================================================
   APP
========================================================= */

function App() {
  const [activePage, setActivePage] = useState("overview");
  const [topSearch, setTopSearch] = useState("");
  const [target, setTarget] = useState("8.8.8.8");
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState("");

  /* =======================================================
     NAVIGATION
  ======================================================= */

  function openPage(page) {
    setActivePage(page);

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  }

  /* =======================================================
     VIRUSTOTAL ANALYZER
  ======================================================= */

  async function analyzeTarget(value = target) {
    const cleanTarget = value.trim();

    if (!cleanTarget) {
      setAnalysisError("Please enter an IP address, domain or URL.");
      return;
    }

    setLoading(true);
    setAnalysisError("");

    try {
      const apiBase = "https://virtual-soc-lab.onrender.com";

      const response = await fetch(
        `${apiBase}/api/analyze?target=${encodeURIComponent(cleanTarget)}`,
      );

      let data = {};

      try {
        data = await response.json();
      } catch {
        throw new Error("Backend returned an invalid response.");
      }

      if (!response.ok) {
        throw new Error(data.error || "Threat analysis failed.");
      }

      setAnalysis(data);
      setTarget(cleanTarget);
    } catch (error) {
      console.error("Analyzer error:", error);

      setAnalysisError(
        error.message || "Unable to connect to the Virtual SOC backend.",
      );
    } finally {
      setLoading(false);
    }
  }

  function handleAnalyzerSubmit(event) {
    event.preventDefault();
    analyzeTarget();
  }

  function handleTopSearch(event) {
    event.preventDefault();

    const value = topSearch.trim();

    if (!value) return;

    setTarget(value);
    setActivePage("overview");
    analyzeTarget(value);
  }

  /* =======================================================
     SIDEBAR
  ======================================================= */

  function Sidebar() {
    return (
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={23} />
          </div>

          <div className="brand-text">
            <h2>VIRTUAL SOC</h2>
            <span>SECURITY LAB</span>
          </div>
        </div>

        <div className="sidebar-divider"></div>

        {navItems.map((group) => (
          <div className="sidebar-section" key={group.group}>
            <p className="section-label">{group.group}</p>

            {group.items.map((item) => {
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  type="button"
                  className={`nav-item ${
                    activePage === item.id ? "active" : ""
                  }`}
                  onClick={() => openPage(item.id)}
                >
                  <Icon size={18} />

                  <span>{item.label}</span>

                  {item.badge && <b className="nav-badge">{item.badge}</b>}
                </button>
              );
            })}
          </div>
        ))}

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot"></span>

            <div>
              <strong>LAB ONLINE</strong>
              <small>Monitoring active</small>
            </div>
          </div>
        </div>
      </aside>
    );
  }

  /* =======================================================
     TOPBAR
  ======================================================= */

  function Topbar() {
    return (
      <header className="topbar">
        <div className="topbar-title">
          <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
          <h1>{pageTitles[activePage]}</h1>
        </div>

        <div className="topbar-right">
          <form className="search-box" onSubmit={handleTopSearch}>
            <Search size={17} />

            <input
              value={topSearch}
              onChange={(e) => setTopSearch(e.target.value)}
              placeholder="Analyze IP, domain or URL..."
            />

            <button type="submit">ANALYZE</button>
          </form>

          <div className="live-indicator">
            <span></span>
            SYSTEM ONLINE
          </div>
        </div>
      </header>
    );
  }

  /* =======================================================
     THREAT ANALYZER
  ======================================================= */

  function ThreatAnalyzer() {
    const stats = analysis?.analysis || {};

    return (
      <section className="analyzer-card">
        <div className="analyzer-header">
          <div className="analyzer-title">
            <div className="analyzer-icon">
              <ScanSearch size={22} />
            </div>

            <div>
              <div className="title-line">
                <h3>Live Threat Analyzer</h3>
                <span className="live-pill">LIVE</span>
              </div>

              <p>
                Real-time IP, domain and URL reputation analysis powered by
                VirusTotal.
              </p>
            </div>
          </div>

          <div className="external-intel">
            <Globe size={16} />
            External threat intelligence
          </div>
        </div>

        <form className="analyzer-search" onSubmit={handleAnalyzerSubmit}>
          <Search size={19} />

          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter IP address, domain or URL..."
          />

          <button type="submit" disabled={loading}>
            {loading ? (
              <>
                <RefreshCw size={16} className="spin" />
                ANALYZING
              </>
            ) : (
              <>
                <Shield size={16} />
                ANALYZE THREAT
              </>
            )}
          </button>
        </form>

        {analysisError && (
          <div className="analyzer-error">
            <AlertTriangle size={17} />
            <span>{analysisError}</span>
          </div>
        )}

        {analysis && (
          <div className="threat-result">
            <div className="result-top">
              <div>
                <span className="result-label">ANALYZED TARGET</span>

                <div className="target-value">{analysis.target}</div>

                <div className="analysis-meta">
                  <Clock3 size={13} />
                  Analyzed at {getTime()}
                  <span>•</span>
                  {analysis.type}
                </div>
              </div>

              <div className={`risk-badge ${riskClass(analysis.verdict)}`}>
                <ShieldAlert size={16} />
                {analysis.verdict}
              </div>
            </div>

            <div className="analysis-grid">
              <div className="analysis-stat malicious">
                <span>MALICIOUS</span>
                <strong>{stats.malicious ?? 0}</strong>
              </div>

              <div className="analysis-stat suspicious">
                <span>SUSPICIOUS</span>
                <strong>{stats.suspicious ?? 0}</strong>
              </div>

              <div className="analysis-stat harmless">
                <span>HARMLESS</span>
                <strong>{stats.harmless ?? 0}</strong>
              </div>

              <div className="analysis-stat undetected">
                <span>UNDETECTED</span>
                <strong>{stats.undetected ?? 0}</strong>
              </div>
            </div>

            <div className="intel-grid">
              {analysis.type === "IP" && (
                <>
                  <InfoBox
                    icon={MapPin}
                    label="COUNTRY"
                    value={analysis.country || "N/A"}
                  />

                  <InfoBox
                    icon={Hash}
                    label="ASN"
                    value={analysis.asn || "N/A"}
                  />

                  <InfoBox
                    icon={Server}
                    label="AS OWNER"
                    value={analysis.as_owner || "N/A"}
                  />

                  <InfoBox
                    icon={Activity}
                    label="REPUTATION"
                    value={analysis.reputation ?? "N/A"}
                  />
                </>
              )}

              {analysis.type === "DOMAIN" && (
                <>
                  <InfoBox
                    icon={Activity}
                    label="REPUTATION"
                    value={analysis.reputation ?? "N/A"}
                  />

                  <InfoBox
                    icon={Database}
                    label="REGISTRAR"
                    value={analysis.registrar || "N/A"}
                  />

                  <InfoBox
                    icon={Clock3}
                    label="LAST ANALYSIS"
                    value={
                      analysis.last_analysis_date
                        ? new Date(
                            analysis.last_analysis_date * 1000,
                          ).toLocaleDateString()
                        : "N/A"
                    }
                  />

                  <InfoBox
                    icon={Globe}
                    label="CATEGORIES"
                    value={
                      analysis.categories
                        ? Object.keys(analysis.categories).length
                        : 0
                    }
                  />
                </>
              )}

              {analysis.type === "URL" && (
                <>
                  <InfoBox
                    icon={Activity}
                    label="REPUTATION"
                    value={analysis.reputation ?? "N/A"}
                  />

                  <InfoBox
                    icon={Globe}
                    label="HTTP STATUS"
                    value={analysis.http_response_code ?? "N/A"}
                  />

                  <InfoBox
                    icon={RefreshCw}
                    label="SUBMISSIONS"
                    value={analysis.times_submitted ?? "N/A"}
                  />

                  <InfoBox
                    icon={FileText}
                    label="TITLE"
                    value={analysis.title || "N/A"}
                  />
                </>
              )}
            </div>

            {analysis.message && (
              <div className="analysis-message">
                <Activity size={15} />
                {analysis.message}
              </div>
            )}
          </div>
        )}
      </section>
    );
  }

  function InfoBox({ icon: Icon, label, value }) {
    return (
      <div className="info-box">
        <div className="info-icon">
          <Icon size={14} />
        </div>

        <div className="info-content">
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      </div>
    );
  }

  /* =======================================================
     OVERVIEW
  ======================================================= */

  function OverviewPage() {
    return (
      <>
        <section className="hero-row">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER</p>

            <h2>Security Overview</h2>

            <p>
              Centralized monitoring of authentication, network and web security
              telemetry.
            </p>
          </div>

          <div className="last-updated">
            <Activity size={16} />
            Live lab telemetry
          </div>
        </section>

        <ThreatAnalyzer />

        <section className="stats-grid">
          <StatCard
            label="Total Alerts"
            value="02"
            subtitle="Security incidents detected"
            icon={Bell}
            type="purple"
          />

          <StatCard
            label="High Severity"
            value="01"
            subtitle="Requires investigation"
            icon={AlertTriangle}
            type="red"
          />

          <StatCard
            label="Medium Severity"
            value="01"
            subtitle="Suspicious activity"
            icon={Shield}
            type="orange"
          />

          <StatCard
            label="Network Events"
            value="03"
            subtitle="DNS + TCP telemetry"
            icon={Network}
            type="green"
          />
        </section>

        <section className="dashboard-grid">
          <div className="panel large-panel">
            <div className="panel-header">
              <div>
                <h3>Threat Activity</h3>
                <span>Security events detected during analysis</span>
              </div>

              <button type="button" className="panel-action">
                7 DAYS
              </button>
            </div>

            <div className="chart">
              <div className="chart-y">
                <span>5</span>
                <span>4</span>
                <span>3</span>
                <span>2</span>
                <span>1</span>
                <span>0</span>
              </div>

              <div className="chart-area">
                <div className="grid-line line-1"></div>
                <div className="grid-line line-2"></div>
                <div className="grid-line line-3"></div>
                <div className="grid-line line-4"></div>

                <div className="bars">
                  {[
                    ["MON", "75%", "purple-bar"],
                    ["TUE", "45%", "blue-bar"],
                    ["WED", "95%", "red-bar"],
                    ["THU", "55%", "purple-bar"],
                    ["FRI", "35%", "blue-bar"],
                    ["SAT", "65%", "red-bar"],
                    ["SUN", "50%", "purple-bar"],
                  ].map(([day, height, cls]) => (
                    <div className="bar-group" key={day}>
                      <div className={`bar ${cls}`} style={{ height }}></div>

                      <span>{day}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="panel severity-panel">
            <div className="panel-header">
              <div>
                <h3>Alert Severity</h3>
                <span>Current incident distribution</span>
              </div>
            </div>

            <div className="donut-wrapper">
              <div className="donut">
                <div className="donut-center">
                  <strong>02</strong>
                  <span>Alerts</span>
                </div>
              </div>
            </div>

            <div className="legend">
              <div>
                <span className="legend-dot red-dot"></span>
                High
                <b>01</b>
              </div>

              <div>
                <span className="legend-dot orange-dot"></span>
                Medium
                <b>01</b>
              </div>

              <div>
                <span className="legend-dot green-dot"></span>
                Low
                <b>00</b>
              </div>
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Recent Security Alerts</h3>
              <span>Latest detections generated by the SOC pipeline</span>
            </div>

            <button
              type="button"
              className="view-all"
              onClick={() => openPage("alerts")}
            >
              View all
              <ChevronRight size={15} />
            </button>
          </div>

          <AlertTable />
        </section>

        <section className="dashboard-grid lower-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Network Telemetry</h3>
                <span>Observed network events</span>
              </div>
            </div>

            <div className="network-list">
              <NetworkSummary
                label="TCP Connections"
                value="02"
                icon={Network}
              />

              <NetworkSummary label="DNS Queries" value="01" icon={Globe} />

              <NetworkSummary label="HTTP 403" value="01" icon={Shield} />
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Investigation Stack</h3>
                <span>Security analysis components</span>
              </div>
            </div>

            <div className="stack-list">
              <StackItem icon={Radar} text="Nmap Reconnaissance" />
              <StackItem icon={Radio} text="Wireshark Packet Capture" />
              <StackItem icon={Terminal} text="Python Detection Engine" />
              <StackItem icon={Server} text="Splunk SIEM Analysis" />
            </div>
          </div>
        </section>
      </>
    );
  }

  /* =======================================================
     SECURITY ALERTS
  ======================================================= */

  function SecurityAlertsPage() {
    return (
      <>
        <PageIntro
          title="Security Alerts"
          description="Detected incidents produced by the Python detection engine and SOC pipeline."
        />

        <section className="stats-grid">
          <StatCard
            label="Total Alerts"
            value="02"
            subtitle="Active detections"
            icon={Bell}
            type="purple"
          />

          <StatCard
            label="High"
            value="01"
            subtitle="Brute force incident"
            icon={AlertTriangle}
            type="red"
          />

          <StatCard
            label="Medium"
            value="01"
            subtitle="HTTP 403 incident"
            icon={Shield}
            type="orange"
          />

          <StatCard
            label="Pipeline"
            value="ON"
            subtitle="Detection engine ready"
            icon={CheckCircle2}
            type="green"
          />
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>All Security Alerts</h3>
              <span>MITRE-ready defensive detections</span>
            </div>
          </div>

          <AlertTable />
        </section>

        <section className="dashboard-grid lower-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Detection Pipeline</h3>
                <span>Alert generation workflow</span>
              </div>
            </div>

            <div className="workflow">
              <Workflow number="01" text="Security logs generated" />

              <Workflow
                number="02"
                text="Python detection engine analyzed events"
              />

              <Workflow number="03" text="Alerts generated" />

              <Workflow number="04" text="SOC dashboard correlation" />
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Analyst Summary</h3>
                <span>Current incident assessment</span>
              </div>
            </div>

            <div className="summary-box danger">
              <AlertTriangle size={19} />

              <div>
                <strong>Brute force activity detected</strong>

                <p>
                  Five failed authentication attempts originated from
                  192.168.56.10.
                </p>
              </div>
            </div>

            <div className="summary-box warning">
              <Shield size={19} />

              <div>
                <strong>Forbidden resource access</strong>

                <p>HTTP 403 response observed for /admin from 192.168.56.30.</p>
              </div>
            </div>
          </div>
        </section>
      </>
    );
  }

  /* =======================================================
     AUTHENTICATION
  ======================================================= */

  function AuthenticationPage() {
    return (
      <>
        <PageIntro
          title="Authentication"
          description="Authentication telemetry and failed-login investigation."
        />

        <section className="stats-grid three">
          <StatCard
            label="Login Events"
            value="07"
            subtitle="Total auth events"
            icon={LockKeyhole}
            type="purple"
          />

          <StatCard
            label="Failed Logins"
            value="05"
            subtitle="From 192.168.56.10"
            icon={AlertTriangle}
            type="red"
          />

          <StatCard
            label="Successful"
            value="02"
            subtitle="Valid sessions"
            icon={CheckCircle2}
            type="green"
          />
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Authentication Events</h3>
              <span>Source: soc_auth</span>
            </div>

            <button
              type="button"
              className="view-all"
              onClick={() => openPage("alerts")}
            >
              Investigate
              <ChevronRight size={15} />
            </button>
          </div>

          <div className="data-table">
            <div className="data-head auth-grid">
              <span>TIME</span>
              <span>EVENT</span>
              <span>USER</span>
              <span>SOURCE IP</span>
              <span>RESULT</span>
            </div>

            {authEvents.map((item, index) => (
              <div className="data-row auth-grid" key={`${item.time}-${index}`}>
                <span className="muted">{item.time}</span>

                <strong>{item.event}</strong>

                <span>{item.user}</span>

                <code>{item.source}</code>

                <span
                  className={`result-pill ${
                    item.result === "FAILED" ? "failed" : "success"
                  }`}
                >
                  {item.result}
                </span>
              </div>
            ))}
          </div>
        </section>
      </>
    );
  }

  /* =======================================================
     NETWORK
  ======================================================= */

  function NetworkPage() {
    return (
      <>
        <PageIntro
          title="Network Activity"
          description="DNS and TCP telemetry collected from the Virtual SOC lab."
        />

        <section className="stats-grid three">
          <StatCard
            label="TCP Connections"
            value="02"
            subtitle="Observed in lab telemetry"
            icon={Network}
            type="green"
          />

          <StatCard
            label="DNS Queries"
            value="01"
            subtitle="Observed in lab telemetry"
            icon={Globe}
            type="green"
          />

          <StatCard
            label="HTTP 403"
            value="01"
            subtitle="Web security event"
            icon={Shield}
            type="orange"
          />
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Network Events</h3>
              <span>Source: soc_network</span>
            </div>
          </div>

          <div className="data-table">
            <div className="data-head network-grid">
              <span>TIME</span>
              <span>EVENT</span>
              <span>SOURCE IP</span>
              <span>DESTINATION</span>
              <span>PROTOCOL</span>
            </div>

            {networkActivity.map((item, index) => (
              <div
                className="data-row network-grid"
                key={`${item.time}-${index}`}
              >
                <span className="muted">{item.time}</span>

                <strong>{item.event}</strong>

                <code>{item.source}</code>

                <span>{item.destination}</span>

                <span className="protocol-pill">{item.protocol}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="dashboard-grid lower-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Traffic Breakdown</h3>
                <span>Network telemetry distribution</span>
              </div>
            </div>

            <div className="traffic-bars">
              <TrafficBar label="TCP" value="2" width="75%" />

              <TrafficBar label="DNS" value="1" width="42%" />

              <TrafficBar label="HTTP" value="1" width="42%" />
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Network Status</h3>
                <span>Lab interface telemetry</span>
              </div>
            </div>

            <div className="status-list">
              <StatusRow label="Lab interface" value="eth1" />
              <StatusRow label="Kali IP" value="10.0.3.15" />
              <StatusRow label="Gateway" value="10.0.3.2" />
              <StatusRow label="Packet capture" value="AVAILABLE" />
            </div>
          </div>
        </section>
      </>
    );
  }

  /* =======================================================
     RECON
  ======================================================= */

  function ReconPage() {
    return (
      <>
        <PageIntro
          title="Reconnaissance"
          description="Authorized lab reconnaissance results collected with Nmap."
        />

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Nmap Service Discovery</h3>
              <span>Lab target: 10.0.3.2</span>
            </div>

            <span className="captured-pill">CAPTURED</span>
          </div>

          <div className="data-table">
            <div className="data-head recon-grid">
              <span>PORT</span>
              <span>STATE</span>
              <span>SERVICE</span>
            </div>

            {nmapResults.map((item) => (
              <div className="data-row recon-grid" key={item.port}>
                <code>{item.port}</code>
                <span className="open-state">{item.state}</span>
                <strong>{item.service}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="dashboard-grid lower-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Recon Workflow</h3>
                <span>Defensive investigation chain</span>
              </div>
            </div>

            <div className="workflow">
              <Workflow number="01" text="Nmap scan executed" />
              <Workflow number="02" text="Scan evidence saved" />
              <Workflow number="03" text="Service inventory reviewed" />
              <Workflow
                number="04"
                text="Results correlated with SOC telemetry"
              />
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Next Step</h3>
                <span>Investigation guidance</span>
              </div>
            </div>

            <div className="next-step">
              <Radar size={25} />

              <strong>
                Compare discovered services with network events and detected
                alerts.
              </strong>
            </div>
          </div>
        </section>
      </>
    );
  }

  /* =======================================================
     PACKET ANALYSIS
  ======================================================= */

  function PacketPage() {
    return (
      <>
        <PageIntro
          title="Packet Analysis"
          description="Wireshark packet capture evidence collected from the authorized lab network."
        />

        <section className="stats-grid three">
          <StatCard
            label="Packets Captured"
            value="25"
            subtitle="Total ICMP packets"
            icon={Radio}
            type="purple"
          />

          <StatCard
            label="Displayed"
            value="20"
            subtitle="ICMP packets displayed"
            icon={Activity}
            type="green"
          />

          <StatCard
            label="Dropped"
            value="00"
            subtitle="Capture packet loss"
            icon={CheckCircle2}
            type="green"
          />
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Wireshark Capture</h3>
              <span>virtual_soc_icmp_capture.pcapng</span>
            </div>

            <span className="captured-pill">CAPTURED</span>
          </div>

          <div className="data-table">
            <div className="data-head packet-grid">
              <span>PACKET</span>
              <span>SOURCE</span>
              <span>DESTINATION</span>
              <span>COUNT</span>
              <span>STATUS</span>
            </div>

            {packetData.map((item, index) => (
              <div
                className="data-row packet-grid"
                key={`${item.packet}-${index}`}
              >
                <strong>{item.packet}</strong>

                <code>{item.source}</code>

                <code>{item.destination}</code>

                <span>{item.packets}</span>

                <span className="result-pill success">{item.status}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Capture Evidence</h3>
              <span>Defensive packet-analysis summary</span>
            </div>
          </div>

          <div className="evidence-grid">
            <Evidence icon={Wifi} title="Interface" value="eth1" />

            <Evidence icon={Globe} title="Filter" value="icmp" />

            <Evidence icon={Activity} title="Packet Loss" value="0" />

            <Evidence icon={FileText} title="Evidence" value="PCAPNG" />
          </div>
        </section>
      </>
    );
  }

  /* =======================================================
     MITRE ATT&CK
  ======================================================= */

  function MitrePage() {
    return (
      <>
        <PageIntro
          title="MITRE ATT&CK"
          description="Security detections mapped to relevant MITRE ATT&CK techniques."
        />

        <section className="stats-grid three">
          <StatCard
            label="Mapped Techniques"
            value="03"
            subtitle="Observed in investigation"
            icon={Target}
            type="purple"
          />

          <StatCard
            label="Credential Access"
            value="01"
            subtitle="Brute force technique"
            icon={LockKeyhole}
            type="red"
          />

          <StatCard
            label="Discovery"
            value="01"
            subtitle="Network service scanning"
            icon={Radar}
            type="orange"
          />
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Technique Mapping</h3>
              <span>Defensive detection correlation</span>
            </div>
          </div>

          <div className="mitre-list">
            {mitreTechniques.map((item) => (
              <div className="mitre-card" key={item.id}>
                <div className="mitre-id">{item.id}</div>

                <div className="mitre-main">
                  <h4>{item.name}</h4>

                  <span className="tactic">{item.tactic}</span>

                  <p>{item.evidence}</p>
                </div>

                <span
                  className={`severity-pill ${item.severity.toLowerCase()}`}
                >
                  {item.severity}
                </span>
              </div>
            ))}
          </div>
        </section>
      </>
    );
  }

  /* =======================================================
     REPORT
  ======================================================= */

  function ReportPage() {
    return (
      <>
        <PageIntro
          title="Investigation Report"
          description="Consolidated findings from the Virtual SOC investigation pipeline."
        />

        <section className="report-header">
          <div>
            <span className="report-kicker">CASE ID</span>

            <strong>VSOC-2026-001</strong>

            <p>Virtual SOC Lab Defensive Investigation</p>
          </div>

          <div className="report-status">
            <CheckCircle2 size={17} />
            INVESTIGATION COMPLETE
          </div>
        </section>

        <section className="dashboard-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Executive Summary</h3>
                <span>Investigation conclusion</span>
              </div>
            </div>

            <div className="report-text">
              <p>
                The Virtual SOC Lab successfully collected authentication,
                network, reconnaissance and packet-analysis evidence from an
                authorized lab environment.
              </p>

              <p>
                The Python detection engine identified repeated failed
                authentication attempts and a forbidden HTTP resource access
                event. These detections were correlated with the SOC monitoring
                workflow.
              </p>

              <p>
                Nmap and Wireshark evidence provided additional visibility into
                exposed services and network traffic.
              </p>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Incident Summary</h3>
                <span>Key findings</span>
              </div>
            </div>

            <div className="incident-summary">
              <SummaryRow label="High severity" value="01" type="high" />

              <SummaryRow label="Medium severity" value="01" type="medium" />

              <SummaryRow label="Network events" value="03" type="normal" />

              <SummaryRow label="Auth events" value="07" type="normal" />
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Investigation Chain</h3>
              <span>End-to-end SOC workflow</span>
            </div>
          </div>

          <div className="chain">
            <ChainStep
              icon={Radar}
              title="Reconnaissance"
              text="Nmap service discovery"
            />

            <ChevronRight className="chain-arrow" />

            <ChainStep
              icon={Radio}
              title="Packet Analysis"
              text="Wireshark evidence"
            />

            <ChevronRight className="chain-arrow" />

            <ChainStep
              icon={Terminal}
              title="Detection"
              text="Python detection engine"
            />

            <ChevronRight className="chain-arrow" />

            <ChainStep icon={Server} title="SIEM" text="Splunk correlation" />

            <ChevronRight className="chain-arrow" />

            <ChainStep
              icon={Shield}
              title="SOC"
              text="Investigation dashboard"
            />
          </div>
        </section>
      </>
    );
  }

  /* =======================================================
     GENERIC COMPONENTS
  ======================================================= */

  function PageIntro({ title, description }) {
    return (
      <section className="hero-row">
        <div>
          <p className="eyebrow">SECURITY OPERATIONS CENTER</p>

          <h2>{title}</h2>

          <p>{description}</p>
        </div>

        <div className="last-updated">
          <Activity size={16} />
          Live lab telemetry
        </div>
      </section>
    );
  }

  function StatCard({ label, value, subtitle, icon: Icon, type }) {
    return (
      <div className={`stat-card ${type}-card`}>
        <div className="stat-top">
          <span>{label}</span>

          <div className={`stat-icon ${type}`}>
            <Icon size={18} />
          </div>
        </div>

        <strong>{value}</strong>

        <small>{subtitle}</small>
      </div>
    );
  }

  function AlertTable() {
    return (
      <div className="alert-table">
        <div className="table-head">
          <span>SEVERITY</span>
          <span>ALERT TYPE</span>
          <span>SOURCE IP</span>
          <span>DESCRIPTION</span>
          <span>TIME</span>
        </div>

        {alerts.map((alert) => (
          <div className="table-row" key={alert.type}>
            <span>
              <span className={`severity-pill ${alert.severity.toLowerCase()}`}>
                {alert.severity}
              </span>
            </span>

            <strong className="alert-type">{alert.type}</strong>

            <code>{alert.source}</code>

            <span className="description">{alert.description}</span>

            <span className="muted">{alert.time}</span>
          </div>
        ))}
      </div>
    );
  }

  function NetworkSummary({ label, value, icon: Icon }) {
    return (
      <div className="network-item">
        <div className="network-icon">
          <Icon size={18} />
        </div>

        <span>{label}</span>

        <strong>{value}</strong>
      </div>
    );
  }

  function StackItem({ icon: Icon, text }) {
    return (
      <div className="stack-item">
        <Icon size={18} />

        <span>{text}</span>

        <CheckCircle2 size={17} className="check" />
      </div>
    );
  }

  function Workflow({ number, text }) {
    return (
      <div className="workflow-item">
        <div className="workflow-number">{number}</div>

        <span>{text}</span>

        <CheckCircle2 size={17} className="check" />
      </div>
    );
  }

  function TrafficBar({ label, value, width }) {
    return (
      <div className="traffic-row">
        <div>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>

        <div className="traffic-track">
          <div className="traffic-fill" style={{ width }}></div>
        </div>
      </div>
    );
  }

  function StatusRow({ label, value }) {
    return (
      <div className="status-row">
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    );
  }

  function Evidence({ icon: Icon, title, value }) {
    return (
      <div className="evidence-card">
        <div className="evidence-icon">
          <Icon size={18} />
        </div>

        <span>{title}</span>

        <strong>{value}</strong>
      </div>
    );
  }

  function SummaryRow({ label, value, type }) {
    return (
      <div className="summary-row">
        <span>{label}</span>

        <strong className={`summary-value ${type}`}>{value}</strong>
      </div>
    );
  }

  function ChainStep({ icon: Icon, title, text }) {
    return (
      <div className="chain-step">
        <div className="chain-icon">
          <Icon size={19} />
        </div>

        <strong>{title}</strong>

        <span>{text}</span>
      </div>
    );
  }

  /* =======================================================
     PAGE ROUTER
  ======================================================= */

  function renderPage() {
    switch (activePage) {
      case "alerts":
        return <SecurityAlertsPage />;

      case "authentication":
        return <AuthenticationPage />;

      case "network":
        return <NetworkPage />;

      case "recon":
        return <ReconPage />;

      case "packets":
        return <PacketPage />;

      case "mitre":
        return <MitrePage />;

      case "report":
        return <ReportPage />;

      case "overview":
      default:
        return <OverviewPage />;
    }
  }

  /* =======================================================
     FINAL LAYOUT
  ======================================================= */

  return (
    <div className="app-shell">
      <Sidebar />

      <main className="main-content">
        <Topbar />

        <div className="page-content">{renderPage()}</div>

        <footer>
          <span>VIRTUAL SOC LAB v1.0</span>

          <span>Security Monitoring & Investigation Platform</span>

          <span>Built for Defensive Security Research</span>
        </footer>
      </main>
    </div>
  );
}

export default App;
