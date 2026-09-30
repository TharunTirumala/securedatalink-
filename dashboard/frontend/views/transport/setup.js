// Setup Card component for configuring and launching Transport sessions

export function createSetupCard(onStart, onStop, onAttackChange, onRepeat) {
  const container = document.createElement('div');
  container.className = 'panel transport-setup-card';

  container.innerHTML = `
    <div class="panel-header">
      <h3>FLIGHT & LINK CONFIGURATION</h3>
      <span class="protection-banner on" id="tr-protect-badge">PROTECTED (CRYPTO ON)</span>
    </div>

    <div class="form-row" style="margin-top:12px;">
      <label class="form-label">TELEMETRY SOURCE</label>
      <select id="tr-source-type" class="tactical-select">
        <option value="drone" selected>Simulated Drone (MAVLink 2 over UDP :14550)</option>
        <option value="synthetic">Synthetic Generator Stream</option>
        <option value="csv">Dataset Upload (CSV / JSON)</option>
      </select>
    </div>

    <div class="form-row" style="margin-top:10px;">
      <label class="form-label" style="display:flex; justify-content:space-between;">
        <span>CRYPTOGRAPHIC PROTECTION</span>
        <strong id="tr-protect-label" style="color:var(--c-cyan);">PROTECT: ON</strong>
      </label>
      <div style="display:flex; gap:10px; margin-top:4px;">
        <button type="button" class="btn-sm active" id="btn-prot-on" style="flex:1;">PROTECTION ON</button>
        <button type="button" class="btn-sm" id="btn-prot-off" style="flex:1; border-color:#ff3366; color:#ff3366;">PROTECTION OFF</button>
      </div>
    </div>

    <div class="form-row" style="margin-top:14px;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <label class="form-label">ADVERSARIAL ATTACK MODE</label>
        <span id="tr-attack-rate-lbl" style="font-family:monospace; font-size:11px; color:#ff3366;">RATE: 100%</span>
      </div>
      <div class="attack-buttons-grid">
        <button class="btn-attack-mode pass active" data-mode="pass">PASS (CLEAN)</button>
        <button class="btn-attack-mode" data-mode="position_rewrite">POS REWRITE</button>
        <button class="btn-attack-mode" data-mode="altitude_rewrite">ALT REWRITE</button>
        <button class="btn-attack-mode" data-mode="gps_freeze">GPS FREEZE</button>
        <button class="btn-attack-mode" data-mode="battery_lie">BATTERY LIE</button>
        <button class="btn-attack-mode" data-mode="tamper">WIRE TAMPER</button>
        <button class="btn-attack-mode" data-mode="drop">WIRE DROP</button>
        <button class="btn-attack-mode" data-mode="replay">WIRE REPLAY</button>
      </div>
      <div style="margin-top:8px;">
        <input type="range" id="tr-attack-rate" min="0" max="100" value="100" style="width:100%;">
      </div>
    </div>

    <!-- Advanced options collapsed by default -->
    <details style="margin-top:12px; font-size:11px; border:1px solid #1a2538; border-radius:4px; padding:6px 10px;">
      <summary style="cursor:pointer; color:#718096;">ADVANCED FLIGHT & SOCKET PARAMETERS</summary>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:8px;">
        <div>
          <label style="color:#718096; font-size:10px;">PACKET COUNT</label>
          <input type="number" id="tr-count" value="100" class="tactical-input" style="width:100%;">
        </div>
        <div>
          <label style="color:#718096; font-size:10px;">RATE (PPS)</label>
          <input type="number" id="tr-rate-pps" value="20" class="tactical-input" style="width:100%;">
        </div>
        <div>
          <label style="color:#718096; font-size:10px;">RE-KEY INTERVAL</label>
          <input type="number" id="tr-rekey-every" value="100" class="tactical-input" style="width:100%;">
        </div>
        <div>
          <label style="color:#718096; font-size:10px;">FLIGHT ROUTE</label>
          <select id="tr-route-pattern" class="tactical-select" style="width:100%;">
            <option value="circle" selected>Circle Orbit</option>
            <option value="square">Square Perimeter</option>
            <option value="survey">Lawnmower Survey</option>
            <option value="random">Random Walk</option>
          </select>
        </div>
        <div>
          <label style="color:#718096; font-size:10px;">FLIGHT SEED</label>
          <input type="number" id="tr-seed" value="${Math.floor(Math.random() * 900000 + 100000)}" class="tactical-input" style="width:100%;">
        </div>
      </div>
    </details>

    <div style="display:flex; gap:8px; margin-top:16px;">
      <button id="btn-tr-start" class="btn btn-primary" style="flex:2;">START SESSION</button>
      <button id="btn-tr-stop" class="btn btn-danger" style="flex:1;" disabled>STOP</button>
      <button id="btn-tr-repeat" class="btn btn-secondary" style="flex:1;">REPEAT</button>
    </div>
    <div id="tr-error-banner" style="display:none; margin-top:12px; padding:10px 12px; background:rgba(255, 51, 102, 0.12); border:1px solid #ff3366; border-radius:4px; font-size:12px; color:#fff;"></div>
  `;

  let currentProtect = true;
  let currentAttackMode = 'pass';
  let currentRate = 1.0;

  const btnProtOn = container.querySelector('#btn-prot-on');
  const btnProtOff = container.querySelector('#btn-prot-off');
  const protectBadge = container.querySelector('#tr-protect-badge');
  const protectLabel = container.querySelector('#tr-protect-label');
  const rateSlider = container.querySelector('#tr-attack-rate');
  const rateLbl = container.querySelector('#tr-attack-rate-lbl');
  const btnStart = container.querySelector('#btn-tr-start');
  const btnStop = container.querySelector('#btn-tr-stop');
  const btnRepeat = container.querySelector('#btn-tr-repeat');

  function updateProtect(prot) {
    currentProtect = prot;
    if (prot) {
      btnProtOn.classList.add('active');
      btnProtOff.classList.remove('active');
      protectBadge.className = 'protection-banner on';
      protectBadge.textContent = 'PROTECTED (CRYPTO ON)';
      protectLabel.textContent = 'PROTECT: ON';
      protectLabel.style.color = 'var(--c-cyan)';
    } else {
      btnProtOff.classList.add('active');
      btnProtOn.classList.remove('active');
      protectBadge.className = 'protection-banner off';
      protectBadge.textContent = 'UNPROTECTED (PASS-THROUGH)';
      protectLabel.textContent = 'PROTECT: OFF (RAW)';
      protectLabel.style.color = '#ff3366';
    }
  }

  btnProtOn.addEventListener('click', () => updateProtect(true));
  btnProtOff.addEventListener('click', () => updateProtect(false));

  const modeButtons = container.querySelectorAll('.btn-attack-mode');
  modeButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      modeButtons.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      currentAttackMode = btn.getAttribute('data-mode');
      if (onAttackChange) {
        onAttackChange(currentAttackMode, currentRate);
      }
    });
  });

  rateSlider.addEventListener('input', (e) => {
    currentRate = parseInt(e.target.value, 10) / 100.0;
    rateLbl.textContent = `RATE: ${e.target.value}%`;
    if (onAttackChange) {
      onAttackChange(currentAttackMode, currentRate);
    }
  });

  btnStart.addEventListener('click', () => {
    const countVal = parseInt(container.querySelector('#tr-count').value, 10);
    const config = {
      source_type: container.querySelector('#tr-source-type').value,
      protect: currentProtect,
      count: !isNaN(countVal) && countVal > 0 ? countVal : 100,
      rate_pps: parseInt(container.querySelector('#tr-rate-pps').value, 10) || 20,
      rekey_every: parseInt(container.querySelector('#tr-rekey-every').value, 10) || 100,
      drone_route: container.querySelector('#tr-route-pattern').value,
      drone_seed: parseInt(container.querySelector('#tr-seed').value, 10) || Math.floor(Math.random() * 900000 + 100000),
      attack_mode: currentAttackMode,
      attack_rate: currentRate,
      attack_params: { lat_offset_deg: 0.005, lon_offset_deg: 0.005, alt_offset_m: 100.0 },
    };
    if (onStart) onStart(config);
  });

  btnStop.addEventListener('click', () => {
    if (onStop) onStop();
  });

  btnRepeat.addEventListener('click', () => {
    if (onRepeat) onRepeat();
  });

  return {
    element: container,
    setRunning(isRunning) {
      btnStart.disabled = isRunning;
      btnStop.disabled = !isRunning;
      btnRepeat.disabled = isRunning;
      if (isRunning) this.hideError();
    },
    showError(message, onRestartAction) {
      const banner = container.querySelector('#tr-error-banner');
      if (!banner) return;
      banner.style.display = 'block';
      banner.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
          <span>${message}</span>
          ${onRestartAction ? '<button type="button" class="btn btn-sm btn-danger" id="btn-tr-banner-restart" style="padding:3px 8px; font-size:11px; white-space:nowrap;">Stop and Restart</button>' : ''}
        </div>
      `;
      if (onRestartAction) {
        const btn = banner.querySelector('#btn-tr-banner-restart');
        if (btn) {
          btn.addEventListener('click', () => {
            banner.style.display = 'none';
            onRestartAction();
          });
        }
      }
    },
    hideError() {
      const banner = container.querySelector('#tr-error-banner');
      if (banner) banner.style.display = 'none';
    },
    getConfig() {
      return {
        source_type: container.querySelector('#tr-source-type').value,
        protect: currentProtect,
        rate_pps: parseInt(container.querySelector('#tr-rate-pps').value, 10) || 20,
        rekey_every: parseInt(container.querySelector('#tr-rekey-every').value, 10) || 100,
        drone_route: container.querySelector('#tr-route-pattern').value,
        drone_seed: parseInt(container.querySelector('#tr-seed').value, 10) || 42,
        attack_mode: currentAttackMode,
        attack_rate: currentRate,
      };
    },
  };
}
