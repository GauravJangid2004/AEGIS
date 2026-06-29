/**
 * AEGIS Dashboard — Client-Side JavaScript
 * Handles page navigation, API calls, WebSocket live feed,
 * step confirmation UI, and live updates.
 */

// ─── Configuration ───────────────────────────────────────
let API_BASE = 'http://localhost:8000';
let activeWebSocket = null;
let activePentestId = null;
let isInteractive = true;

// ─── Page Navigation ─────────────────────────────────────
function showPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    // Show selected page
    const page = document.getElementById(`page-${pageId}`);
    if (page) page.classList.add('active');

    const navItem = document.querySelector(`.nav-item[data-page="${pageId}"]`);
    if (navItem) navItem.classList.add('active');
}

// ─── API Helpers ─────────────────────────────────────────
async function apiCall(endpoint, method = 'GET', body = null) {
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' },
    };
    if (body) options.body = JSON.stringify(body);

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        return await response.json();
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        return null;
    }
}

// ─── Health Check ────────────────────────────────────────
async function checkApiHealth() {
    const dot = document.getElementById('api-status-dot');
    const text = document.getElementById('api-status-text');

    try {
        const result = await apiCall('/api/health');
        if (result && result.status === 'healthy') {
            dot.className = 'status-dot online';
            text.textContent = 'API Connected';
        } else {
            throw new Error('unhealthy');
        }
    } catch {
        dot.className = 'status-dot offline';
        text.textContent = 'API Offline';
    }
}

// ─── Start Scan ──────────────────────────────────────────
async function startScan(event) {
    event.preventDefault();

    const target = document.getElementById('scan-target').value.trim();
    const scope = document.getElementById('scan-scope').value;
    const depth = document.getElementById('scan-depth').value;
    const maxIterations = parseInt(document.getElementById('scan-iterations').value);
    const consent = document.getElementById('scan-consent').checked;
    const interactiveEl = document.getElementById('scan-interactive');
    isInteractive = interactiveEl ? interactiveEl.checked : true;

    if (!target) return alert('Please enter a target');
    if (!consent) return alert('You must confirm authorization');

    const btn = document.getElementById('btn-start-scan');
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">⏳</span> Starting...';

    const result = await apiCall('/api/pentest/start', 'POST', {
        target,
        scope,
        depth,
        max_iterations: maxIterations,
        interactive: isInteractive,
    });

    if (result && result.id) {
        activePentestId = result.id;
        connectWebSocket(result.id);

        // Switch to live page
        showPage('live');
        document.getElementById('live-target').textContent = `Target: ${target}`;
        document.getElementById('live-badge').textContent = 'SCANNING';
        document.getElementById('live-badge').classList.add('active');
        document.getElementById('btn-stop-scan').disabled = false;

        // Show/hide auto mode toggle
        const autoToggle = document.getElementById('auto-mode-toggle');
        if (autoToggle) {
            autoToggle.style.display = 'inline-flex';
            const checkbox = document.getElementById('auto-mode-checkbox');
            if (checkbox) checkbox.checked = !isInteractive;
        }

        const modeLabel = isInteractive ? 'INTERACTIVE' : 'AUTO';
        addTerminalLine('system', `AEGIS Autonomous Pentest started on ${target}`);
        addTerminalLine('system', `Scope: ${scope} | Depth: ${depth} | Mode: ${modeLabel}`);
        addTerminalLine('system', `Pentest ID: ${result.id}`);
        addTerminalLine('system', '─'.repeat(60));

        // Update dashboard
        updateDashboard();
    } else {
        alert('Failed to start scan. Is the API server running?');
    }

    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">🚀</span> Launch Autonomous Pentest';
}

// ─── Stop Scan ───────────────────────────────────────────
async function stopScan() {
    if (!activePentestId) return;

    const result = await apiCall(`/api/pentest/${activePentestId}/stop`, 'POST');
    if (result) {
        addTerminalLine('system', '⏹ Scan stop requested...');
        document.getElementById('btn-stop-scan').disabled = true;
        hideSuggestionPanel();
    }
}

// ─── Toggle Auto Mode ────────────────────────────────────
async function toggleAutoMode() {
    if (!activePentestId) return;

    const result = await apiCall(`/api/pentest/${activePentestId}/auto`, 'POST');
    if (result) {
        isInteractive = result.interactive;
        const checkbox = document.getElementById('auto-mode-checkbox');
        if (checkbox) checkbox.checked = !isInteractive;

        if (!isInteractive) {
            hideSuggestionPanel();
            addTerminalLine('system', '⚡ Switched to AUTO mode — no more confirmations');
        } else {
            addTerminalLine('system', '🔄 Switched to INTERACTIVE mode — confirmations required');
        }
    }
}

// ─── Confirm Step ────────────────────────────────────────
async function confirmStep(choiceIndex) {
    if (!activePentestId || !activeWebSocket) return;

    // Send via WebSocket for low latency
    activeWebSocket.send(JSON.stringify({
        type: 'confirm',
        choice: choiceIndex,
    }));

    hideSuggestionPanel();
    addTerminalLine('success', `✔ Confirmed suggestion #${choiceIndex + 1}`);
}

// ─── Skip Step ───────────────────────────────────────────
async function skipStep() {
    if (!activePentestId || !activeWebSocket) return;

    activeWebSocket.send(JSON.stringify({ type: 'skip' }));

    hideSuggestionPanel();
    addTerminalLine('system', '⏭ Step skipped');
}

// ─── WebSocket Connection ────────────────────────────────
function connectWebSocket(pentestId) {
    if (activeWebSocket) {
        activeWebSocket.close();
    }

    const wsUrl = API_BASE.replace('http', 'ws') + `/ws/${pentestId}`;
    activeWebSocket = new WebSocket(wsUrl);

    activeWebSocket.onopen = () => {
        console.log('WebSocket connected');
        addTerminalLine('system', '🔌 Live feed connected');
    };

    activeWebSocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleLiveEvent(data);
    };

    activeWebSocket.onclose = () => {
        console.log('WebSocket disconnected');
        addTerminalLine('system', '🔌 Live feed disconnected');
        document.getElementById('live-badge').textContent = 'COMPLETED';
        document.getElementById('live-badge').classList.remove('active');
        document.getElementById('btn-stop-scan').disabled = true;
        hideSuggestionPanel();
        updateDashboard();
    };

    activeWebSocket.onerror = (error) => {
        console.error('WebSocket error:', error);
    };

    // Keep alive ping
    setInterval(() => {
        if (activeWebSocket && activeWebSocket.readyState === WebSocket.OPEN) {
            activeWebSocket.send('ping');
        }
    }, 30000);
}

// ─── Handle Live Events ──────────────────────────────────
function handleLiveEvent(event) {
    switch (event.type) {
        case 'phase_start':
            addTerminalLine('system', `\n═══ PHASE: ${event.phase.toUpperCase()} ═══`);
            break;

        case 'step_start':
            addTerminalLine('reasoning', `\n📌 Step ${event.step}: ${event.reasoning || ''}`);
            addTerminalLine('command', event.command || '');
            break;

        case 'step_complete':
            const icon = event.status === 'success' ? '✅' : '❌';
            const lineClass = event.status === 'success' ? 'success' : 'error';
            addTerminalLine(lineClass, `${icon} Step ${event.step}: ${event.status}`);

            if (event.output_preview) {
                addTerminalLine('output', event.output_preview.substring(0, 300));
            }
            break;

        case 'step_suggestions':
            showSuggestionPanel(event);
            addTerminalLine('system', `\n🤖 AI suggests ${event.suggestions?.length || 0} next actions — awaiting your choice...`);
            break;

        case 'step_confirmed':
            addTerminalLine('success', `✔ Running suggestion #${(event.choice || 0) + 1}`);
            break;

        case 'step_skipped':
            addTerminalLine('system', `⏭ Step skipped`);
            break;

        case 'confirmation_ack':
            // Server acknowledged our confirmation
            break;

        case 'skip_ack':
            break;

        case 'auto_ack':
            isInteractive = event.interactive;
            break;

        case 'finding':
            addFinding(event);
            break;

        case 'pentest_complete':
            addTerminalLine('success', '\n🎉 PENTEST COMPLETE');
            addTerminalLine('system', `Overall Risk: ${event.chain?.overall_risk || 'N/A'}`);
            addTerminalLine('system', `Total Findings: ${event.chain?.total_findings || 0}`);
            document.getElementById('live-badge').textContent = 'COMPLETED';
            document.getElementById('live-badge').classList.remove('active');
            hideSuggestionPanel();
            updateDashboard();
            break;

        case 'pentest_error':
            addTerminalLine('error', `\n❌ ERROR: ${event.error}`);
            hideSuggestionPanel();
            break;

        case 'pong':
            break; // ignore keepalive response

        default:
            console.log('Unknown event:', event);
    }
}

// ─── Suggestion Panel ────────────────────────────────────
function showSuggestionPanel(event) {
    const panel = document.getElementById('suggestion-panel');
    if (!panel) return;

    const suggestions = event.suggestions || [];
    const assessment = event.overall_assessment || '';
    const phase = (event.phase || '').replace('_', ' ');
    const iteration = event.iteration;
    const maxIter = event.max_iterations;

    let headerText = `AI Recommendations — ${phase}`;
    if (iteration) headerText += ` (Step ${iteration}/${maxIter})`;

    let html = `
        <div class="suggestion-header">
            <div class="suggestion-title">
                <span class="suggestion-icon">🤖</span>
                <h3>${headerText}</h3>
            </div>
            <div class="suggestion-actions-top">
                <button class="btn btn-sm btn-ghost" onclick="skipStep()" title="Skip this step">
                    ⏭ Skip
                </button>
                <button class="btn btn-sm btn-ghost" onclick="toggleAutoMode()" title="Switch to auto mode">
                    ⚡ Auto
                </button>
            </div>
        </div>
    `;

    if (assessment) {
        html += `<div class="suggestion-assessment">${assessment}</div>`;
    }

    html += '<div class="suggestion-cards">';

    suggestions.forEach((s, i) => {
        const risk = s.risk_level || 'low';
        const confidence = s.confidence || 0;
        const confPercent = Math.round(confidence * 100);
        const category = s.category || '';
        const categoryIcons = {
            recon: '🔍', exploit: '💥', enum: '📋',
            bruteforce: '🔑', 'post-exploit': '🏴'
        };
        const catIcon = categoryIcons[category] || '🔧';
        const isTop = i === 0;

        html += `
            <div class="suggestion-card ${isTop ? 'top-pick' : ''}" onclick="confirmStep(${i})">
                <div class="suggestion-card-header">
                    <span class="suggestion-rank ${isTop ? 'rank-top' : ''}">${isTop ? '★' : ''} #${i + 1}</span>
                    <span class="risk-badge risk-${risk}">${risk.toUpperCase()}</span>
                </div>
                <div class="suggestion-tool">
                    <span class="tool-icon">${catIcon}</span>
                    <span class="tool-name">${s.tool || 'unknown'}</span>
                </div>
                <div class="suggestion-command">${escapeHtml(s.command || 'N/A')}</div>
                <div class="suggestion-reasoning">${escapeHtml(s.reasoning || '')}</div>
                <div class="suggestion-footer">
                    <div class="confidence-bar-container">
                        <div class="confidence-label">Confidence</div>
                        <div class="confidence-bar">
                            <div class="confidence-fill confidence-${confidence >= 0.8 ? 'high' : confidence >= 0.5 ? 'med' : 'low'}"
                                 style="width: ${confPercent}%"></div>
                        </div>
                        <span class="confidence-value">${confPercent}%</span>
                    </div>
                    <button class="btn btn-sm btn-primary suggestion-run-btn" onclick="event.stopPropagation(); confirmStep(${i})">
                        ▶ Run This
                    </button>
                </div>
            </div>
        `;
    });

    html += '</div>';

    panel.innerHTML = html;
    panel.classList.add('visible');

    // Scroll terminal to show suggestion panel
    const terminal = document.getElementById('ai-terminal');
    if (terminal) terminal.scrollTop = terminal.scrollHeight;
}

function hideSuggestionPanel() {
    const panel = document.getElementById('suggestion-panel');
    if (panel) {
        panel.classList.remove('visible');
        panel.innerHTML = '';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ─── Terminal Output ─────────────────────────────────────
function addTerminalLine(type, text) {
    const terminal = document.getElementById('ai-terminal');
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = text;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

// ─── Add Finding to Live Panel ───────────────────────────
function addFinding(data) {
    const container = document.getElementById('live-findings');

    // Remove empty state
    const emptyState = container.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const item = document.createElement('div');
    item.className = `finding-item severity-${data.severity || 'info'}`;
    item.innerHTML = `
        <span class="finding-badge ${data.severity || 'info'}">${(data.severity || 'info').toUpperCase()}</span>
        <div class="finding-title">${data.title || 'Finding'}</div>
        <div class="finding-desc">${data.description || ''}</div>
    `;
    container.insertBefore(item, container.firstChild);
}

// ─── Update Dashboard ────────────────────────────────────
async function updateDashboard() {
    const result = await apiCall('/api/pentests');
    if (!result) return;

    document.getElementById('stat-active').textContent = result.active?.length || 0;
    document.getElementById('stat-completed').textContent = result.completed?.length || 0;

    // Update recent scans list
    const scanList = document.getElementById('recent-scans-list');
    const allScans = [
        ...(result.active || []).map(s => ({ ...s, statusClass: 'running', statusText: 'Running' })),
        ...(result.completed || []).map(id => ({ id, statusClass: 'completed', statusText: 'Completed', target: id })),
    ];

    if (allScans.length > 0) {
        scanList.innerHTML = allScans.map(scan => `
            <div class="scan-list-item">
                <div class="scan-info">
                    <h4>${scan.target || scan.id}</h4>
                    <p>${scan.scope || 'full'} scope • ${scan.overall_risk || 'N/A'} risk</p>
                </div>
                <span class="scan-status ${scan.statusClass}">${scan.statusText}</span>
            </div>
        `).join('');
    }
}

// ─── Load Models ─────────────────────────────────────────
async function loadModels() {
    const result = await apiCall('/api/models');
    if (!result) return;

    if (result.configured) {
        document.getElementById('model-reasoning').textContent = result.configured.reasoning;
        document.getElementById('model-code').textContent = result.configured.code;
        document.getElementById('model-report').textContent = result.configured.report;
        document.getElementById('model-vuln').textContent = result.configured.vulnerability;
    }

    const list = document.getElementById('available-models-list');
    if (result.models && result.models.length > 0) {
        list.innerHTML = '<button class="btn btn-secondary" onclick="loadModels()" style="margin-bottom:1rem">🔄 Refresh</button>';
        result.models.forEach(model => {
            const div = document.createElement('div');
            div.className = 'scan-list-item';
            div.innerHTML = `
                <div class="scan-info">
                    <h4 style="font-family:var(--font-mono)">${model.name}</h4>
                </div>
                <span class="scan-status completed">✅ Available</span>
            `;
            list.appendChild(div);
        });
    }
}

// ─── Settings ────────────────────────────────────────────
function updateApiUrl(url) {
    API_BASE = url.replace(/\/$/, '');
    checkApiHealth();
}

// ─── Initialize ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    checkApiHealth();
    setInterval(checkApiHealth, 15000);
    updateDashboard();
});
