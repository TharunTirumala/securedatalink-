// Polling coordinator for live transport counters and telemetry

export function createTransportPoller({ liveCard, droneCard, setupCard, onFinished }) {
  let pollInterval = null;
  let isFetching = false;
  let hasTransmitted = false;

  function start() {
    stop();
    hasTransmitted = false;
    isFetching = false;

    pollInterval = setInterval(async () => {
      if (isFetching) return;
      isFetching = true;

      try {
        const resp = await fetch('/api/transport/status?live=1');
        if (!resp.ok) return;
        const data = await resp.json();

        // 1. Session info and counters
        if (data.session_id) {
          liveCard.setSessionInfo(data.session_id, data.seed);
        }
        if (data.counters) {
          liveCard.updateCounters(data.counters);
        }

        // 2. Live telemetry update (drone, c2, divergence)
        if (data.live) {
          droneCard.updateTelemetry(data.live.drone, data.live.c2, data.live.divergence_m);
        }

        // 3. Status transition from STARTING PROCESSES... to ACTIVE // TRANSMITTING
        const sent = data.counters ? (data.counters.sent || 0) : 0;
        const hasDrone = Boolean(data.live && data.live.drone);
        if (!hasTransmitted && (sent > 0 || hasDrone)) {
          hasTransmitted = true;
          liveCard.setStatus('ACTIVE // TRANSMITTING', '#00ff88');
        }

        // 4. Session termination check
        if (data.state === 'finished' || data.state === 'stopped' || data.state === 'idle') {
          stop();
          setupCard.setRunning(false);
          liveCard.setStatus(data.session_id ? 'FINISHED // READY' : 'IDLE // READY', 'var(--c-cyan)');
          if (onFinished && data.session_id) {
            onFinished(data.session_id);
          }
        }
      } catch (err) {
        // Quiet poll error
      } finally {
        isFetching = false;
      }
    }, 250);
  }

  function stop() {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    isFetching = false;
  }

  return { start, stop };
}
