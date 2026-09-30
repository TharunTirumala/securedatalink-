const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const ARTIFACT_DIR = 'C:\\Users\\sarie\\.gemini\\antigravity\\brain\\b18cb8a0-db14-4b9e-817d-8eca5f45e8a8';

async function main() {
  const edgePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  const port = 9225;
  const edgeProc = spawn(edgePath, [
    `--remote-debugging-port=${port}`,
    '--headless=new',
    '--disable-gpu',
    '--window-size=1600,1050',
    'about:blank'
  ]);

  await new Promise((r) => setTimeout(r, 1200));

  const listRes = await fetch(`http://127.0.0.1:${port}/json`);
  const pages = await listRes.json();
  const page = pages.find((p) => p.type === 'page' && !p.url.startsWith('chrome-extension://')) || pages[0];
  const ws = new WebSocket(page.webSocketDebuggerUrl);

  let id = 1;
  const pending = new Map();
  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.method === 'Runtime.consoleAPICalled') {
      console.log('BROWSER LOG:', data.params.args.map((a) => a.value || a.description).join(' '));
    }
    if (data.id && pending.has(data.id)) {
      pending.get(data.id)(data.result);
      pending.delete(data.id);
    }
  };

  function send(method, params = {}) {
    return new Promise((resolve) => {
      const msgId = id++;
      pending.set(msgId, resolve);
      ws.send(JSON.stringify({ id: msgId, method, params }));
    });
  }

  await new Promise((r) => { ws.onopen = r; });
  await send('Page.enable');
  await send('Runtime.enable');

  console.log('Navigating to http://127.0.0.1:8000/#/transport...');
  await send('Page.navigate', { url: 'http://127.0.0.1:8000/#/transport' });
  await new Promise((r) => setTimeout(r, 2000));

  // Screenshot 1: Setup and Initial Transport View
  console.log('Capturing Screenshot 1: Transport Initial State...');
  const shot1 = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(ARTIFACT_DIR, 'transport_setup_initial.png'), Buffer.from(shot1.data, 'base64'));

  // Start Session programmatically
  console.log('Starting Live Transport Session...');
  await send('Runtime.evaluate', {
    expression: `
      (() => {
        const btn = document.getElementById('btn-tr-start');
        if (btn) btn.click();
      })()
    `
  });

  // Wait while UDP datagrams stream and live canvas animates
  console.log('Streaming UDP packets and waiting for counters...');
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 500));
    const evalRes = await send('Runtime.evaluate', {
      expression: `(() => {
        const recv = document.getElementById('cnt-recv');
        const rows = document.querySelectorAll('#tr-feed-tbody tr');
        return {
          recv: recv ? parseInt(recv.textContent, 10) : 0,
          rows: rows.length
        };
      })()`,
      returnByValue: true
    });
    const val = evalRes.result ? evalRes.result.value : {};
    if (val.recv > 0) {
      console.log(`Feed populated: ${val.recv} received, ${val.rows} table rows.`);
      await new Promise((r) => setTimeout(r, 1000));
      break;
    }
  }

  // Screenshot 2: Live Transmitting Flight & Pipeline
  console.log('Capturing Screenshot 2: Live Transmitting Flight & Pipeline...');
  const shot2 = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(ARTIFACT_DIR, 'transport_live_flight.png'), Buffer.from(shot2.data, 'base64'));

  // Stop Session
  console.log('Stopping Transport Session...');
  await send('Runtime.evaluate', {
    expression: `
      (() => {
        const btn = document.getElementById('btn-tr-stop');
        if (btn) btn.click();
      })()
    `
  });

  await new Promise((r) => setTimeout(r, 1500));

  // Switch to Reconciliation Tab
  console.log('Switching to Reconciliation Tab...');
  await send('Runtime.evaluate', {
    expression: `
      (() => {
        const tab = document.getElementById('tab-tr-reconcile');
        if (tab) tab.click();
      })()
    `
  });

  await new Promise((r) => setTimeout(r, 1200));

  // Screenshot 3: Reconciliation Report & Audit
  console.log('Capturing Screenshot 3: Reconciliation Audit...');
  const shot3 = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(ARTIFACT_DIR, 'transport_reconciliation_audit.png'), Buffer.from(shot3.data, 'base64'));

  console.log('All screenshots captured successfully!');
  ws.close();
  edgeProc.kill();
  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
