#!/usr/bin/env node
/**
 * Home SOC Dashboard Server
 * Simple HTTP server to serve the threat dashboard
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

const server = http.createServer((req, res) => {
  let filePath = req.url === '/' ? '/index.html' : req.url;
  
  // Determine which directory to serve from
  let baseDir = PUBLIC_DIR;
  if (filePath.startsWith('/data/')) {
    baseDir = __dirname;
  }
  
  filePath = path.join(baseDir, filePath);
  
  // Security: prevent directory traversal
  if (!filePath.startsWith(PUBLIC_DIR) && !filePath.startsWith(DATA_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }
  
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'text/plain';
  
  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404);
        res.end('404 Not Found');
      } else {
        res.writeHead(500);
        res.end('500 Internal Server Error');
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
});

server.listen(PORT, () => {
  console.log(`🛡️  Home SOC Dashboard running on http://localhost:${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}`);
  console.log(`🔄 Auto-refreshes every 5 minutes`);
  console.log('\nPress Ctrl+C to stop');
});
