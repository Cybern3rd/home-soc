# Home SOC - AI-Powered Home Network Security

**Started:** 2026-02-17 03:33 UTC  
**Owner:** Neo + Jackson  
**Priority:** P1 - CRITICAL (Security)

## Objective
Build an AI-powered Security Operations Center (SOC) for home network monitoring, threat detection, and automated response.

## Credentials & Resources
- **Email:** neo_pm@agentmail.to
- **AgentMail API:** (Stored securely in environment variable $AGENTMAIL_API_KEY)
- **Infrastructure Options:** GitHub, Cloudflare, Kestra, VPS
- **Decision Authority:** Full autonomy on architecture and hosting choices

## Core Features

### 1. Network Monitoring
- Real-time traffic analysis
- Device discovery and fingerprinting
- Bandwidth monitoring per device
- Connection tracking (who's talking to whom)

### 2. Threat Detection
- Anomaly detection using ML
- Known malware/C2 signatures
- Suspicious behavior patterns
- Port scan detection
- DDoS attempt identification

### 3. Alerting & Response
- Real-time alerts via Discord/Telegram/Email
- Severity classification (Critical, High, Medium, Low, Info)
- Automated response actions (block IP, quarantine device)
- Incident timeline and forensics

### 4. AI-Powered Analysis
- Natural language threat summaries
- Pattern recognition across time
- Predictive threat modeling
- Automated triage and prioritization

### 5. Dashboard & Reporting
- Web UI for real-time status
- Historical analytics
- Device inventory
- Threat intelligence feed integration

## Architecture Options

### Option A: Lightweight VPS-Hosted
**Deployment:** VPS (current server)
- Agent on home network (lightweight collector)
- Data pipeline to VPS
- Processing/analysis on VPS
- Cloudflare Pages dashboard
**Pros:** Simple, centralized, easy to manage
**Cons:** Data leaves network, requires VPN/secure tunnel

### Option B: Hybrid Local + Cloud
**Deployment:** Raspberry Pi/Local + Cloudflare Workers
- Heavy processing locally
- Alerts/analytics to cloud
- Cloudflare Workers for API/dashboard
**Pros:** Data stays local, cloud for access
**Cons:** Requires local hardware

### Option C: Pure Cloud with Agents
**Deployment:** Cloudflare Workers + Kestra orchestration
- Network flow logs sent to cloud
- Kestra workflows for analysis
- D1 for storage
- Workers for real-time processing
**Pros:** Fully managed, scalable
**Cons:** Higher latency, data egress

## Technology Stack (Recommended)

### Data Collection
- **Network Tap:** Mirror port / span port
- **Agent:** tcpdump, Zeek, Suricata (IDS)
- **Logs:** syslog, netflow, pcap

### Processing & Analysis
- **Stream Processing:** Kestra workflows
- **ML/AI:** Cloudflare AI Workers, OpenAI for summaries
- **Signature Matching:** Suricata rules, YARA
- **Threat Intel:** abuse.ch, GreyNoise, AlienVault OTX

### Storage
- **Time-series:** InfluxDB or Cloudflare D1
- **Events:** SQLite or D1
- **Long-term:** S3/R2 for PCAP archives

### Dashboard
- **Frontend:** Astro + React (like ops-workflow-engine)
- **Hosting:** Cloudflare Pages
- **Real-time:** WebSocket via Durable Objects
- **Visualization:** Recharts, D3.js

### Alerting
- **Email:** AgentMail
- **Discord:** Webhook integration
- **Telegram:** Bot API

## Phase 1: MVP (Week 8)
1. **Basic network monitoring**
   - Packet capture on VPS or local
   - Device discovery
   - Traffic stats

2. **Simple threat detection**
   - Port scan detection
   - Known bad IP blocking (threat feeds)
   - Bandwidth anomalies

3. **Basic dashboard**
   - Live device list
   - Recent alerts
   - Traffic graphs

4. **Alert system**
   - Discord notifications
   - Email via AgentMail

## Phase 2: AI Enhancement
- Natural language summaries
- Behavior baseline learning
- Automated response actions
- Predictive warnings

## Phase 3: Advanced Features
- PCAP analysis on-demand
- Threat hunting queries
- Integration with security tools
- Multi-site support

## Success Metrics
- **Detection accuracy:** >95% true positive rate
- **Response time:** Alerts within 30 seconds of incident
- **Coverage:** All network devices monitored
- **Usability:** Non-technical user can understand threats

---

**Decision:** Starting with Option A (VPS-hosted) for rapid MVP, can migrate to hybrid later.

**Next Steps:**
1. Set up network monitoring on VPS (or test locally)
2. Integrate threat intelligence feeds
3. Build basic dashboard
4. Test with known attack patterns
