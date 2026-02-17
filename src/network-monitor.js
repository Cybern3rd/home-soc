#!/usr/bin/env node
/**
 * Home SOC - Network Monitoring Module
 * Lightweight network security monitoring
 */

const { exec } = require('child_process');
const https = require('https');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  checkInterval: 60000, // 1 minute
  alertWebhook: process.env.DISCORD_WEBHOOK_URL || null,
  logFile: path.join(__dirname, '../logs/network-monitor.log'),
  stateFile: path.join(__dirname, '../data/network-state.json'),
  threatsFile: path.join(__dirname, '../data/threats.json')
};

// Threat Intelligence Sources (Free APIs)
const THREAT_FEEDS = {
  abuseipdb: 'https://api.abuseipdb.com/api/v2/check',
  greynoise: 'https://api.greynoise.io/v3/community/'
};

/**
 * Get current network connections
 */
function getNetworkConnections() {
  return new Promise((resolve, reject) => {
    exec('ss -tunapl', (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      
      const lines = stdout.split('\n').slice(1); // Skip header
      const connections = lines
        .filter(line => line.trim())
        .map(line => {
          const parts = line.split(/\s+/);
          return {
            protocol: parts[0],
            state: parts[1],
            recv_q: parts[2],
            send_q: parts[3],
            local: parts[4],
            peer: parts[5],
            process: parts[6] || 'unknown'
          };
        });
      
      resolve(connections);
    });
  });
}

/**
 * Get listening ports
 */
function getListeningPorts() {
  return new Promise((resolve, reject) => {
    exec('ss -tuln | grep LISTEN', (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      
      const lines = stdout.split('\n');
      const ports = lines
        .filter(line => line.trim())
        .map(line => {
          const parts = line.split(/\s+/);
          const localAddr = parts[4] || '';
          const port = localAddr.split(':').pop();
          return {
            protocol: parts[0],
            port: port,
            address: localAddr
          };
        });
      
      resolve(ports);
    });
  });
}

/**
 * Check IP reputation (basic)
 */
async function checkIPReputation(ip) {
  // For now, just check if it's a private IP
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^localhost$/
  ];
  
  const isPrivate = privateRanges.some(range => range.test(ip));
  
  return {
    ip,
    isPrivate,
    reputation: isPrivate ? 'internal' : 'unknown',
    checked: new Date().toISOString()
  };
}

/**
 * Detect anomalies
 */
function detectAnomalies(currentState, previousState) {
  const anomalies = [];
  
  if (!previousState) return anomalies;
  
  // Check for new listening ports
  const prevPorts = new Set(previousState.ports.map(p => p.port));
  const newPorts = currentState.ports.filter(p => !prevPorts.has(p.port));
  
  if (newPorts.length > 0) {
    anomalies.push({
      type: 'new_listening_port',
      severity: 'medium',
      details: newPorts,
      timestamp: new Date().toISOString()
    });
  }
  
  // Check for unusual connection count
  const connCount = currentState.connections.length;
  const prevConnCount = previousState.connections.length;
  const threshold = prevConnCount * 2; // 2x increase is suspicious
  
  if (connCount > threshold && connCount > 50) {
    anomalies.push({
      type: 'connection_spike',
      severity: 'high',
      details: {
        previous: prevConnCount,
        current: connCount,
        increase: `${Math.round((connCount / prevConnCount - 1) * 100)}%`
      },
      timestamp: new Date().toISOString()
    });
  }
  
  // Check for connections to uncommon ports
  const suspiciousPorts = [4444, 5555, 6666, 8888, 31337, 12345];
  const suspiciousConns = currentState.connections.filter(conn => {
    const peerPort = conn.peer ? parseInt(conn.peer.split(':').pop()) : 0;
    return suspiciousPorts.includes(peerPort);
  });
  
  if (suspiciousConns.length > 0) {
    anomalies.push({
      type: 'suspicious_port',
      severity: 'critical',
      details: suspiciousConns,
      timestamp: new Date().toISOString()
    });
  }
  
  return anomalies;
}

/**
 * Send alert to Discord
 */
function sendAlert(alert) {
  if (!CONFIG.alertWebhook) {
    console.log('⚠️  Alert (no webhook configured):', alert);
    return;
  }
  
  const payload = JSON.stringify({
    content: `🚨 **Security Alert**\n**Type:** ${alert.type}\n**Severity:** ${alert.severity}\n**Details:** \`\`\`json\n${JSON.stringify(alert.details, null, 2)}\n\`\`\``,
    username: 'Home SOC Bot'
  });
  
  const url = new URL(CONFIG.alertWebhook);
  const options = {
    hostname: url.hostname,
    path: url.pathname + url.search,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': payload.length
    }
  };
  
  const req = https.request(options, (res) => {
    if (res.statusCode !== 204) {
      console.error('Failed to send alert:', res.statusCode);
    }
  });
  
  req.on('error', (err) => {
    console.error('Error sending alert:', err);
  });
  
  req.write(payload);
  req.end();
}

/**
 * Load previous state
 */
function loadState() {
  try {
    if (fs.existsSync(CONFIG.stateFile)) {
      return JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading state:', err);
  }
  return null;
}

/**
 * Save current state
 */
function saveState(state) {
  try {
    const dir = path.dirname(CONFIG.stateFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(CONFIG.stateFile, JSON.stringify(state, null, 2));
  } catch (err) {
    console.error('Error saving state:', err);
  }
}

/**
 * Main monitoring loop
 */
async function monitor() {
  console.log('🛡️  Home SOC Network Monitor Starting...\n');
  
  while (true) {
    try {
      const timestamp = new Date().toISOString();
      console.log(`\n[${timestamp}] Running network scan...`);
      
      // Get current state
      const connections = await getNetworkConnections();
      const ports = await getListeningPorts();
      
      const currentState = {
        timestamp,
        connections,
        ports,
        stats: {
          totalConnections: connections.length,
          establishedConnections: connections.filter(c => c.state === 'ESTAB').length,
          listeningPorts: ports.length
        }
      };
      
      console.log(`✅ Connections: ${currentState.stats.totalConnections} (${currentState.stats.establishedConnections} established)`);
      console.log(`✅ Listening Ports: ${currentState.stats.listeningPorts}`);
      
      // Load previous state
      const previousState = loadState();
      
      // Detect anomalies
      const anomalies = detectAnomalies(currentState, previousState);
      
      if (anomalies.length > 0) {
        console.log(`\n🚨 Detected ${anomalies.length} anomalies:`);
        anomalies.forEach(anomaly => {
          console.log(`   - [${anomaly.severity.toUpperCase()}] ${anomaly.type}`);
          sendAlert(anomaly);
        });
      } else {
        console.log('✅ No anomalies detected');
      }
      
      // Save current state
      saveState(currentState);
      
      // Wait before next check
      await new Promise(resolve => setTimeout(resolve, CONFIG.checkInterval));
      
    } catch (error) {
      console.error('❌ Error in monitoring loop:', error);
      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5s on error
    }
  }
}

// Export for testing
module.exports = {
  getNetworkConnections,
  getListeningPorts,
  checkIPReputation,
  detectAnomalies,
  sendAlert
};

// Run if executed directly
if (require.main === module) {
  monitor().catch(console.error);
}
