// Drone Telemetry & Divergence Visualizer with Canvas Flight Track

export function createDroneCard() {
  const container = document.createElement('div');
  container.className = 'panel transport-drone-card';

  container.innerHTML = `
    <div class="panel-header">
      <h3>UAV FLIGHT TELEMETRY & DIVERGENCE</h3>
      <span class="hud-pill" id="tr-drone-mode">AUTO // NAV</span>
    </div>

    <!-- Live Telemetry Variables -->
    <div class="flight-stats-grid" style="margin-top:10px;">
      <div class="flight-stat-tile"><div class="stat-label">LATITUDE</div><div class="stat-val" id="d-lat">37.77490</div></div>
      <div class="flight-stat-tile"><div class="stat-label">LONGITUDE</div><div class="stat-val" id="d-lon">-122.41940</div></div>
      <div class="flight-stat-tile"><div class="stat-label">ALTITUDE</div><div class="stat-val" id="d-alt">100.0 m</div></div>
      <div class="flight-stat-tile"><div class="stat-label">BATTERY</div><div class="stat-val" id="d-bat" style="color:#00ff88;">100%</div></div>
    </div>

    <!-- Live Position Divergence Metric -->
    <div class="divergence-indicator">
      <div>
        <div style="font-size:10px; color:#718096; text-transform:uppercase;">TRUTH VS C2 DIVERGENCE</div>
        <div style="font-size:11px; color:#a0aec0;">Difference between actual UAV flight and C2 display</div>
      </div>
      <div class="divergence-val safe" id="tr-divergence-val">0.0 m</div>
    </div>

    <!-- 2D Canvas Radar Flight Track -->
    <div style="margin-top:12px;">
      <canvas class="flight-map-canvas" id="tr-flight-canvas" width="400" height="200"></canvas>
    </div>
  `;

  const latEl = container.querySelector('#d-lat');
  const lonEl = container.querySelector('#d-lon');
  const altEl = container.querySelector('#d-alt');
  const batEl = container.querySelector('#d-bat');
  const divEl = container.querySelector('#tr-divergence-val');
  const canvas = container.querySelector('#tr-flight-canvas');
  const ctx = canvas.getContext('2d');

  const truthTrail = [];
  const c2Trail = [];
  let homeLat = 37.7749;
  let homeLon = -122.4194;
  let isWaiting = false;

  function setWaiting(waiting) {
    isWaiting = Boolean(waiting);
    if (isWaiting) {
      latEl.textContent = '--';
      lonEl.textContent = '--';
      altEl.textContent = '--';
      batEl.textContent = '--';
      divEl.textContent = '--';
      divEl.className = 'divergence-val safe';
      truthTrail.length = 0;
      c2Trail.length = 0;
    }
    renderRadar();
  }

  function renderRadar() {
    if (!ctx) return;
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    if (isWaiting) {
      ctx.fillStyle = '#718096';
      ctx.font = '12px monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('WAITING FOR TELEMETRY...', w / 2, h / 2);
      return;
    }

    // Draw radar grid
    ctx.strokeStyle = '#141f30';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(w / 2, h / 2, 40, 0, Math.PI * 2);
    ctx.arc(w / 2, h / 2, 80, 0, Math.PI * 2);
    ctx.moveTo(w / 2, 0); ctx.lineTo(w / 2, h);
    ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2);
    ctx.stroke();

    // Map function
    const scale = 8000;
    const toX = (lon) => w / 2 + (lon - homeLon) * scale;
    const toY = (lat) => h / 2 - (lat - homeLat) * scale;

    // Draw Truth Trail (Cyan)
    if (truthTrail.length > 1) {
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.7)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      truthTrail.forEach((pt, i) => {
        const x = toX(pt.lon), y = toY(pt.lat);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    // Draw C2 Trail (Green or Red)
    if (c2Trail.length > 1) {
      ctx.strokeStyle = 'rgba(255, 51, 102, 0.8)';
      ctx.lineWidth = 2;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      c2Trail.forEach((pt, i) => {
        const x = toX(pt.lon), y = toY(pt.lat);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Draw Drone Blip
    if (truthTrail.length > 0) {
      const last = truthTrail[truthTrail.length - 1];
      ctx.fillStyle = '#00e5ff';
      ctx.beginPath();
      ctx.arc(toX(last.lon), toY(last.lat), 4, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  return {
    element: container,
    setWaiting,
    updateTelemetry(drone, c2, divergenceM) {
      if (drone) {
        if (isWaiting) isWaiting = false;
        if (drone.lat != null) latEl.textContent = drone.lat.toFixed(5);
        if (drone.lon != null) lonEl.textContent = drone.lon.toFixed(5);
        if (drone.alt_m != null || drone.alt != null) {
          altEl.textContent = `${(drone.alt_m || drone.alt).toFixed(1)} m`;
        }
        if (drone.battery_pct != null || drone.bat != null) {
          const b = drone.battery_pct != null ? drone.battery_pct : drone.bat;
          batEl.textContent = `${b.toFixed(0)}%`;
        }
        if (drone.lat && drone.lon) {
          truthTrail.push({ lat: drone.lat, lon: drone.lon });
          if (truthTrail.length > 120) truthTrail.shift();
        }
      }

      if (c2 && c2.lat && c2.lon) {
        c2Trail.push({ lat: c2.lat, lon: c2.lon });
        if (c2Trail.length > 120) c2Trail.shift();
      }

      if (divergenceM !== undefined && divergenceM !== null) {
        divEl.textContent = `${divergenceM.toFixed(1)} m`;
        divEl.className = divergenceM > 5.0 ? 'divergence-val diverged' : 'divergence-val safe';
      }

      renderRadar();
    },
    reset() {
      setWaiting(true);
    }
  };
}
