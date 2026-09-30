# Frontend Verification Checklist (Phase 3 Shell & Views)

This checklist tracks regression verification for the SecureLink modular ES frontend.

- [x] **Sidebar Shell Navigation**: Clicking `Live Monitor`, `Dynamic Re-keying`, and `File Lab` activates the corresponding hash route (`#/monitor`, `#/rekey`, `#/lab`) and highlights the active item with cyan accent border.
- [x] **Locked Navigation Rails**: `Adaptive Filter (Phase 4)` and `Transport (Phase 5)` items are styled as locked/dimmed and are non-interactive.
- [x] **Persistent WebSocket & State**: Single WebSocket connection survives route navigation without disconnection; ring buffer backfills events when switching back to Monitor.
- [x] **Sidebar Status Footer**: Connection dot, connection label (`LIVE WS` / `MOCK FEED` / `OFFLINE`), active key epoch, and short run ID render live.
- [x] **Simulation Controls**: `START` and `STOP` simulation requests execute cleanly; controls disable/enable according to run state.
- [x] **Counters & Metrics**: Total, Authentic, Tampered, Replayed, Spoofed, Dropped, and Attack Mitigation % update with 100ms render throttle.
- [x] **Epoch Transitions**: Inline epoch divider rows (`─── ROTATION TO KEY EPOCH X ───`) render cleanly upon key rotation.
- [x] **Operator Controls**: `FORCE RE-KEY` increments epoch; `BLOCK` / `UNBLOCK` updates sender state and reflects status pill.
- [x] **Audit & Incident Acking**: Security violations populate the Incident Stream; clicking `ACK` marks the incident acknowledged and dims the card.
- [x] **Latency Chart**: Chart.js canvas initializes and plots p50 and p99 verification latency trends in real-time.
- [x] **Mock Mode**: Running with `?mock=1` or selecting Mock Feed successfully generates synthetic streaming events without requiring a live run.
- [x] **No Console Errors**: Modern ES modules load cleanly with zero runtime syntax or unhandled rejection errors.

## File Lab Decluttered Stepper & Verification

- [x] **Step-by-Step Stepper & Accordion**: Exactly one step card is expanded at a time; completed steps collapse into a single-line summary with an `[Edit]` button. Auto-advance on import or upload.
- [x] **Educational Banner**: Single-line dismissible banner at top of lab; dismissal persists across tab navigation in session.
- [x] **Step 1 Import**: Clean drag-and-drop zone with single primary `[Encrypt & Sign]` button; collapsed advanced options hint; column dropdown; properly padded 3-row sample table; synthetic 100-frame generator.
- [x] **Step 2 Wire File**: Compact card showing filename, frame count, and `Keys OK` badge; side-by-side `[Download wire file (.txt)]` and `[Upload edited file]`; collapsed plaintext vs ciphertext and cheat sheet.
- [x] **Step 3 Attack Workbench**: Sub-tabs for `[Edit by Hand]` (default) and `[Quick Attack in Browser]`; attacks and frame inspector run in 420px slide-over drawer; collapsible active edit log with undo buttons.
- [x] **Step 4 Verify & Results**: Dual verify buttons (`[Verify baseline]` with green 100% authentic banner, `[Verify working copy]`); 5-tile summary strip (`Authentic`, `Rejected`, `FALSE ACCEPTS` (red if >0), `False Rejects`, `Gaps`); expandable sequence gap details; 3 tabs (Verdicts, Clean C2 Stream, Reconciliation Audit).
- [x] **Shared Frame Table**: Notepad line numbers ($n+1$), sticky header, 25 rows/page pagination, filters (`All`, `Edited`, `Rejected`, `Authentic`, `False Accepts`, `False Rejects`), and collapsible column toggles.
- [x] **Slide-over Drawer**: Fixed 420px right-hand overlay with backdrop, dismissible via `Esc` key, backdrop click, or `✕` button without shifting page layout.
- [x] **Error Callout & Formatting**: `formatError(err)` handles FastAPI validation arrays, JSON objects, network disconnects, and presents a red callout with `[Retry]`; verify buttons disable with `"Verifying..."` state while running.
- [x] **Upload & Edit Decoupling**: Uploading an edited wire file records inferred labels in `.inferred.json` without cluttering `.edits.json`, displaying `"N changes detected · 0 active edits"`.
- [x] **Parent Baseline Verification**: Verifying baseline on an uploaded file verifies the pristine parent capture (100% authentic); disables button with tooltip if file has no parent.
- [x] **Sidebar Route Activation**: Sidebar highlights strictly match `#nav-item.active` on route changes without sticky active states across views.
- [x] **Auto-Scroll Summary Strip**: Successful verification smoothly scrolls `#verify-summary-strip` into view.
- [x] **File Lab Results Monitor Parity**: Verdict counter tiles (`AUTHENTIC`, `TAMPERED`, `REPLAYED`, `SPOOFED`, `DROPPED`, `OTHER`, `TOTAL`) and interactive stacked distribution proportion bar.
- [x] **2/3 Wire Feed + 1/3 Incident Stream**: Left pane shows wire-ordered feed (lines 1..N) with sticky headers, epoch dividers, and ghost rows for dropped frames; right pane shows in-memory incident log with local ACK and click-to-scroll cross-linking.
- [x] **Canonical 8 Columns Alignment**: Consistent 8 columns (`SEQ`, `EPOCH`, `SRC`, `VERDICT`, `REASON`, `TRUTH`, `LATENCY`, `TIMESTAMP`) across Live Monitor and File Lab.
- [x] **Ground Truth Detection Badges**: `CAUGHT` (dim green) and `MISSED` (red/amber) badges displayed alongside ground truth.
- [x] **Clean Baseline Comparison Strip**: Compares untouched baseline vs working copy authentic frames and suppressed count.
- [x] **Export Tools**: Direct download of `.wire` frame file and clean C2 stream `.csv`.
