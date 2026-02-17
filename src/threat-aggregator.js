#!/usr/bin/env node
/**
 * Home SOC - Threat Intelligence Aggregator
 * Fetches and aggregates threat intel from multiple free sources
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '../data');
const CACHE_FILE = path.join(DATA_DIR, 'threat-cache.json');

// Free Threat Intel APIs
const SOURCES = {
  // GreyNoise Community API (free, no key needed for basic)
  greynoise: {
    name: 'GreyNoise',
    url: 'https://api.greynoise.io/v3/community/',
    method: 'GET',
    rateLimit: '60/hour',
  },
  
  // AbuseIPDB (free tier: 1000 req/day)
  abuseipdb: {
    name: 'AbuseIPDB',
    url: 'https://api.abuseipdb.com/api/v2/check',
    method: 'GET',
    headers: {
      'Key': process.env.ABUSEIPDB_API_KEY || '',
      'Accept': 'application/json'
    },
    rateLimit: '1000/day',
  },
  
  // Ransomware.live (completely free)
  ransomware: {
    name: 'Ransomware.live',
    url: 'https://api.ransomware.live/v2/recentvictims',
    method: 'GET',
    rateLimit: 'unlimited',
  },
  
  // URLhaus (abuse.ch - free)
  urlhaus: {
    name: 'URLhaus',
    url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    method: 'POST',
    rateLimit: 'fair use',
  },
  
  // ThreatFox (abuse.ch - free)
  threatfox: {
    name: 'ThreatFox',
    url: 'https://threatfox-api.abuse.ch/api/v1/',
    method: 'POST',
    body: { query: 'get_iocs', days: 1 },
    rateLimit: 'fair use',
  }
};

/**
 * HTTP(S) request wrapper
 */
function httpRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const requestOptions = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: options.headers || {},
    };

    const req = https.request(requestOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({
            statusCode: res.statusCode,
            body: data,
            json: data ? JSON.parse(data) : null
          });
        } catch (err) {
          reject(new Error(`Failed to parse JSON: ${err.message}`));
        }
      });
    });

    req.on('error', reject);

    if (options.body) {
      req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    }

    req.end();
  });
}

/**
 * Fetch recent ransomware victims
 */
async function fetchRansomwareVictims() {
  console.log('🔄 Fetching ransomware victims...');
  
  try {
    const response = await httpRequest(SOURCES.ransomware.url);
    const victims = response.json;
    
    console.log(`✅ Found ${victims.length} recent victims`);
    
    return {
      source: 'Ransomware.live',
      timestamp: new Date().toISOString(),
      count: victims.length,
      items: victims.slice(0, 10).map(v => ({
        type: 'victim',
        name: v.post_title || 'Unknown',
        group: v.group_name,
        date: v.discovered,
        country: v.country,
        url: v.post_url,
        severity: 'high'
      }))
    };
  } catch (error) {
    console.error('❌ Ransomware fetch failed:', error.message);
    return { source: 'Ransomware.live', error: error.message, items: [] };
  }
}

/**
 * Fetch recent malicious URLs
 */
async function fetchMaliciousURLs() {
  console.log('🔄 Fetching malicious URLs...');
  
  try {
    const response = await httpRequest(SOURCES.urlhaus.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    const data = response.json;
    const urls = data.urls || [];
    
    console.log(`✅ Found ${urls.length} malicious URLs`);
    
    return {
      source: 'URLhaus',
      timestamp: new Date().toISOString(),
      count: urls.length,
      items: urls.slice(0, 10).map(u => ({
        type: 'url',
        url: u.url,
        threat: u.threat,
        tags: u.tags,
        date: u.dateadded,
        status: u.url_status,
        severity: 'medium'
      }))
    };
  } catch (error) {
    console.error('❌ URLhaus fetch failed:', error.message);
    return { source: 'URLhaus', error: error.message, items: [] };
  }
}

/**
 * Fetch recent IOCs from ThreatFox
 */
async function fetchIOCs() {
  console.log('🔄 Fetching IOCs from ThreatFox...');
  
  try {
    const response = await httpRequest(SOURCES.threatfox.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { query: 'get_iocs', days: 1 }
    });
    
    const data = response.json;
    const iocs = data.data || [];
    
    console.log(`✅ Found ${iocs.length} IOCs`);
    
    return {
      source: 'ThreatFox',
      timestamp: new Date().toISOString(),
      count: iocs.length,
      items: iocs.slice(0, 10).map(i => ({
        type: 'ioc',
        ioc_type: i.ioc_type,
        value: i.ioc,
        threat: i.threat_type,
        malware: i.malware,
        confidence: i.confidence_level,
        date: i.first_seen,
        severity: i.confidence_level >= 75 ? 'high' : 'medium'
      }))
    };
  } catch (error) {
    console.error('❌ ThreatFox fetch failed:', error.message);
    return { source: 'ThreatFox', error: error.message, items: [] };
  }
}

/**
 * Aggregate all threat intel
 */
async function aggregateThreats() {
  console.log('🚀 Home SOC Threat Aggregator Starting...\n');
  
  const results = await Promise.allSettled([
    fetchRansomwareVictims(),
    fetchMaliciousURLs(),
    fetchIOCs()
  ]);
  
  const threats = results.map(r => r.status === 'fulfilled' ? r.value : { error: r.reason.message });
  
  // Calculate summary
  const summary = {
    timestamp: new Date().toISOString(),
    sources: threats.map(t => ({
      name: t.source,
      status: t.error ? 'error' : 'ok',
      count: t.count || 0
    })),
    totalThreats: threats.reduce((sum, t) => sum + (t.items?.length || 0), 0),
    highSeverity: threats.reduce((sum, t) => 
      sum + (t.items?.filter(i => i.severity === 'high').length || 0), 0
    ),
  };
  
  const output = {
    summary,
    threats
  };
  
  // Save to cache
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  
  fs.writeFileSync(CACHE_FILE, JSON.stringify(output, null, 2));
  console.log(`\n✅ Threat data cached to: ${CACHE_FILE}`);
  
  // Print summary
  console.log('\n📊 Summary:');
  console.log(`   Total Threats: ${summary.totalThreats}`);
  console.log(`   High Severity: ${summary.highSeverity}`);
  console.log(`   Sources:`);
  summary.sources.forEach(s => {
    const status = s.status === 'ok' ? '✅' : '❌';
    console.log(`     ${status} ${s.name}: ${s.count} items`);
  });
  
  return output;
}

// Run if executed directly
if (require.main === module) {
  aggregateThreats().catch(console.error);
}

module.exports = { aggregateThreats, fetchRansomwareVictims, fetchMaliciousURLs, fetchIOCs };
