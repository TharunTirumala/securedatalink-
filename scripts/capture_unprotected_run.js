const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const ARTIFACT_DIR = 'C:\\Users\\sarie\\.gemini\\antigravity\\brain\\b18cb8a0-db14-4b9e-817d-8eca5f45e8a8';

async function main() {
  const edgePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  const port = 9226;
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

  await send('Page.navigate', { url: 'http://127.0.0.1:8000/#/transport' });
  await new Promise((r) => setTimeout(r, 1500));

  // Configure Protection OFF and Position Rewrite Attack
  console.log('Configuring Unprotected Run with Position Rewrite...');
  await send('Runtime.evaluate', {
    expression: `
      (() => {
        document.getElementById('btn-prot-off').click();
        const posBtn = document.querySelector('[data-mode="position_rewrite"]');
        if (posBtn) posBtn.click();
        document.getElementById('btn-tr-start').click();
      })()
    `
  });

  console.log('Streaming unprotected MAVLink with position rewrite for 3.5s...');
  await new Promise((r) => setTimeout(r, 3500));

  console.log('Capturing Screenshot: Unprotected Live Attack...');
  const shot1 = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(ARTIFACT_DIR, 'transport_unprotected_attack.png'), Buffer.from(shot1.data, 'base64'));

  // Stop session
  await send('Runtime.evaluate', {
    expression: `document.getElementById('btn-tr-stop').click();`
  });
  await new Promise((r) => setTimeout(r, 1500));

  // Switch to reconciliation
  await send('Runtime.evaluate', {
    expression: `document.getElementById('tab-tr-reconcile').click();`
  });
  await new Promise((r) => setTimeout(r, 1200));

  console.log('Capturing Screenshot: Unprotected Reconciliation Audit...');
  const shot2 = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(ARTIFACT_DIR, 'transport_unprotected_reconcile.png'), Buffer.from(shot2.data, 'base64'));

  console.log('Unprotected run screenshots captured!');
  ws.close();
  edgeProc.kill();
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
