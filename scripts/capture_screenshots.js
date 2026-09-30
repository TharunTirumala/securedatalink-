const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const CLEAN_FID = 'af2850e1492c4e00bd4f0863d91f86e0';
const ATTACKED_FID = '6d77ae96d80e4d5e93d1f48202e284b6';

async function main() {
  const edgePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  const port = 9223;
  const edgeProc = spawn(edgePath, [
    `--remote-debugging-port=${port}`,
    '--headless=new',
    '--disable-gpu',
    '--window-size=1600,1100',
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

  console.log('Navigating to http://127.0.0.1:8000/#/lab...');
  await send('Page.navigate', { url: 'http://127.0.0.1:8000/#/lab' });
  await new Promise((r) => setTimeout(r, 1500));

  // --- 1. Clean File Screenshot ---
  console.log('Testing Clean File Results...');
  await send('Runtime.evaluate', {
    expression: `
      (async () => {
        for (let i = 0; i < 30; i++) {
          const sel = document.getElementById('step2-file-select');
          if (sel && sel.value) break;
          await new Promise(r => setTimeout(r, 100));
        }

        const sel = document.getElementById('step2-file-select');
        if (sel) {
          sel.value = '${CLEAN_FID}';
          sel.dispatchEvent(new Event('change'));
        }
        await new Promise(r => setTimeout(r, 600));

        const item4 = document.querySelector('.stepper-item[data-step="4"]');
        if (item4) item4.click();
        await new Promise(r => setTimeout(r, 400));

        const btnB = document.getElementById('btn-verify-baseline');
        if (btnB) btnB.click();
        await new Promise(r => setTimeout(r, 200));
        while (btnB && btnB.disabled) await new Promise(r => setTimeout(r, 100));

        const skipB = document.querySelector('.btn-feed-skip');
        console.log('Clean skipB found:', Boolean(skipB));
        if (skipB) skipB.click();
        await new Promise(r => setTimeout(r, 400));

        const cleanRows = document.querySelectorAll('.feed-tbody tr.feed-row').length;
        console.log('Clean rows in DOM:', cleanRows);

        const s4 = document.getElementById('step-4-card');
        if (s4) s4.scrollIntoView({ behavior: 'instant', block: 'start' });
      })()
    `,
    awaitPromise: true,
  });

  await new Promise((r) => setTimeout(r, 800));
  const cleanShot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync('docs/screenshots/lab_results_clean.png', Buffer.from(cleanShot.data, 'base64'));
  console.log('Saved docs/screenshots/lab_results_clean.png');

  // --- 2. Attacked File Screenshot ---
  console.log('Testing Attacked File Results...');
  await send('Runtime.evaluate', {
    expression: `
      (async () => {
        const item2 = document.querySelector('.stepper-item[data-step="2"]');
        if (item2) item2.click();
        await new Promise(r => setTimeout(r, 400));

        const sel = document.getElementById('step2-file-select');
        if (sel) {
          sel.value = '${ATTACKED_FID}';
          sel.dispatchEvent(new Event('change'));
        }
        await new Promise(r => setTimeout(r, 1200));

        const item4 = document.querySelector('.stepper-item[data-step="4"]');
        if (item4) item4.click();
        await new Promise(r => setTimeout(r, 500));

        const btnW = document.getElementById('btn-verify-working');
        if (btnW) btnW.click();
        await new Promise(r => setTimeout(r, 200));
        while (btnW && btnW.disabled) await new Promise(r => setTimeout(r, 100));

        const skipW = document.querySelector('.btn-feed-skip');
        console.log('Attacked skipW found:', Boolean(skipW));
        if (skipW) skipW.click();
        await new Promise(r => setTimeout(r, 600));

        const attRows = document.querySelectorAll('.feed-tbody tr.feed-row').length;
        const incCount = document.querySelectorAll('#lab-incidents-host .incident-item').length;
        console.log('Attacked rows in DOM:', attRows, 'Incidents in DOM:', incCount);

        const s4 = document.getElementById('step-4-card');
        if (s4) s4.scrollIntoView({ behavior: 'instant', block: 'start' });
      })()
    `,
    awaitPromise: true,
  });

  await new Promise((r) => setTimeout(r, 800));
  const attShot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync('docs/screenshots/lab_results_attacked.png', Buffer.from(attShot.data, 'base64'));
  console.log('Saved docs/screenshots/lab_results_attacked.png');

  // --- 3. Live Monitor Aligned Columns Screenshot ---
  console.log('Testing Live Monitor feed alignment...');
  await send('Page.navigate', { url: 'http://127.0.0.1:8000/#/monitor?mock=1' });
  await new Promise((r) => setTimeout(r, 1000));
  await send('Runtime.evaluate', {
    expression: `
      (async () => {
        const startBtn = document.getElementById('btn-start');
        if (startBtn && !startBtn.disabled) startBtn.click();
      })()
    `,
    awaitPromise: true,
  });
  await new Promise((r) => setTimeout(r, 3000));
  const monShot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync('docs/screenshots/monitor_aligned.png', Buffer.from(monShot.data, 'base64'));
  console.log('Saved docs/screenshots/monitor_aligned.png');

  edgeProc.kill();
  process.exit(0);
}

main().catch((err) => {
  console.error('Error during capture:', err);
  process.exit(1);
});
