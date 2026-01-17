// Simple WebSocket client test for PMOND /ws2 with detailed logging
const WebSocket = require('ws');

console.log('Connecting to PMOND WebSocket at ws://127.0.0.1:8081/ws2');

// Connect to the WebSocket endpoint
const ws = new WebSocket('ws://127.0.0.1:8081/ws2');

ws.on('open', function open() {
  console.log('Connected to PMOND /ws2 WebSocket');
  console.log('Waiting for welcome message...');
});

ws.on('message', function message(data) {
    console.log('Received message:', data.toString());
    ws.close();
});

ws.on('error', function error(err) {
  console.log('WebSocket error:', err.message);
});

ws.on('close', function close() {
  console.log('Disconnected from PMOND /ws2 WebSocket');
});

// Sleep to prevent immediate exit
setTimeout(() => {
  console.log('Test completed');
}, 1000);
