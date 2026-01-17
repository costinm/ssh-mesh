// Simple WebSocket client test for PMOND with detailed logging
const WebSocket = require('ws');

console.log('Connecting to PMOND WebSocket at ws://127.0.0.1:8081/ws');

// Connect to the WebSocket endpoint
const ws = new WebSocket('ws://127.0.0.1:8081/ws');

ws.on('open', function open() {
  console.log('Connected to PMOND WebSocket');
  console.log('Waiting for process data...');
});

ws.on('message', function message(data) {
  try {
    const processes = JSON.parse(data);
    console.log(`Received process data with ${Object.keys(processes).length} processes`);
    
    // Show first 3 processes as examples
    const processIds = Object.keys(processes);
    console.log('\nFirst 3 processes:');
    for (let i = 0; i < Math.min(3, processIds.length); i++) {
      const pid = processIds[i];
      const process = processes[pid];
      console.log(`  PID: ${process.pid}, PPID: ${process.ppid}, Command: ${process.comm}`);
    }
    
    // Close connection after receiving data
    console.log('\nClosing connection...');
    ws.close();
  } catch (e) {
    console.log('Received non-JSON message:', data.toString());
  }
});

ws.on('error', function error(err) {
  console.log('WebSocket error:', err.message);
});

ws.on('close', function close() {
  console.log('Disconnected from PMOND WebSocket');
});

// Sleep to prevent immediate exit
setTimeout(() => {
  console.log('Test completed');
}, 1000);

