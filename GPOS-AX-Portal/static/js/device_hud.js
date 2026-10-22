// device_hud.js
// Dedicated controller for the Device Agent HUD view to separate logic from main portal files.

class DeviceHUD {
    constructor() {
        this.currentIp = 'None';
        
        // Load boards from local storage or use defaults
        try {
            const storedBoards = localStorage.getItem('gpos_device_boards');
            this.boards = storedBoards ? JSON.parse(storedBoards) : [];
            if (!Array.isArray(this.boards)) this.boards = [];
        } catch (e) {
            this.boards = [];
        }
        
        this.isInitialized = false;
        this.telemetryInterval = null;
    }

    init() {
        if (this.isInitialized) return;
        
        console.log("Initializing Device HUD...");
        this.bindEvents();
        this.renderBoardRegistry();
        this.startTelemetrySimulation();
        this.pingAllBoards();
        this.updateTargetIp(this.boards.length > 0 ? this.boards[0].ip : 'None');
        this.loadArtifactVault();
        this.isInitialized = true;
    }

    async loadArtifactVault() {
        const tbody = document.getElementById('artifact-vault-list');
        if (!tbody) return;
        
        try {
            const token = localStorage.getItem('auth_token');
            const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
            const res = await fetch('/api/artifacts', { headers });
            if (res.status === 401) { return; }
            if (!res.ok) return;
            const data = await res.json();
            const artifacts = data.artifacts || [];
            
            if (artifacts.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-center py-8 text-slate-500 text-sm">Vault is empty.<br>Ask the agent to download logs, take snapshots, or run benchmarks to generate artifacts.</td></tr>`;
                return;
            }
            
            let html = '';
            for (let a of artifacts) {
                let badgeColor = 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
                let icon = 'file-text';
                if (a.type === 'Log Archive') {
                    badgeColor = 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
                    icon = 'archive';
                } else if (a.type === 'Interactive Flamegraph') {
                    badgeColor = 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
                    icon = 'flame';
                } else if (a.type === 'Screen Snapshot') {
                    badgeColor = 'bg-purple-500/20 text-purple-400 border border-purple-500/30';
                    icon = 'camera';
                }
                
                html += `
                    <tr class="hover:bg-slate-700/30 transition-colors">
                        <td class="px-4 py-3 font-mono text-xs text-white flex items-center gap-2">
                            <i data-lucide="${icon}" class="w-4 h-4 text-slate-400"></i>
                            <span class="truncate max-w-[200px]" title="${a.name}">${a.name}</span>
                        </td>
                        <td class="px-4 py-3">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeColor}">${a.type}</span>
                        </td>
                        <td class="px-4 py-3 text-xs text-slate-400 font-mono">${a.size}</td>
                        <td class="px-4 py-3 text-right">
                            <a href="${a.url}" download="${a.name}" target="_blank" class="px-2.5 py-1 bg-emerald-600/80 hover:bg-emerald-500 text-white rounded text-xs font-medium inline-flex items-center gap-1 transition-colors no-underline">
                                <i data-lucide="download" class="w-3 h-3"></i> Download
                            </a>
                        </td>
                    </tr>
                `;
            }
            tbody.innerHTML = html;
            if (typeof lucide !== 'undefined') lucide.createIcons();
        } catch (e) {
            console.error("Error loading artifact vault:", e);
        }
    }

    async pingAllBoards() {
        // Run a quick check on all registered boards to update their status dots
        for (let board of this.boards) {
            try {
                const token = localStorage.getItem('auth_token');
                const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
                const response = await fetch(`/api/device/info?ip=${board.ip}`, { headers });
                if (response.status === 401) { API.logout(); return; }
                if (response.ok) {
                    const data = await response.json();
                    if (data.target === "Unknown Device" || data.os === "Error") {
                        board.status = 'offline';
                    } else {
                        board.status = 'online';
                    }
                } else {
                    board.status = 'offline';
                }
            } catch (e) {
                board.status = 'offline';
            }
        }
        localStorage.setItem('gpos_device_boards', JSON.stringify(this.boards));
        this.renderBoardRegistry();
    }

    bindEvents() {
        const addBtn = document.getElementById('btn-add-board');
        const inputEl = document.getElementById('new-target-ip');

        if (addBtn && inputEl) {
            addBtn.addEventListener('click', () => {
                const ip = inputEl.value.trim();
                if (ip && !this.boards.find(b => b.ip === ip)) {
                    this.boards.push({ id: `target-${Math.floor(Math.random()*1000)}`, ip: ip, status: 'online' });
                    localStorage.setItem('gpos_device_boards', JSON.stringify(this.boards));
                    inputEl.value = '';
                    this.renderBoardRegistry();
                    this.updateTargetIp(ip);
                }
            });
            inputEl.addEventListener('keypress', (e) => {
                if(e.key === 'Enter') addBtn.click();
            });
        }
    }

    renderBoardRegistry() {
        const listEl = document.getElementById('board-registry-list');
        if (!listEl) return;
        
        listEl.innerHTML = '';
        this.boards.forEach(board => {
            const div = document.createElement('div');
            const isActive = this.currentIp === board.ip;
            const statusColor = board.status === 'online' ? 'bg-emerald-500' : 'bg-red-500';
            
            if (isActive) {
                const isOnline = board.status === 'online';
                const cardClass = isOnline 
                    ? 'board-item-online border-emerald-500 bg-gradient-to-r from-emerald-950/60 via-slate-800 to-slate-800 active-board-glow'
                    : 'board-item-offline border-red-500/80 bg-gradient-to-r from-red-950/50 via-slate-800 to-slate-800 active-board-offline-glow';
                const barColor = isOnline 
                    ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,1)]' 
                    : 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.8)]';
                const iconColor = isOnline ? 'text-emerald-400' : 'text-red-400';
                const textColor = isOnline ? 'text-emerald-300/90' : 'text-red-300/80';
                const badgeHtml = isOnline
                    ? '<span class="board-badge text-[9px] font-extrabold tracking-wider uppercase px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-400/50 animate-pulse">ACTIVE</span>'
                    : '<span class="board-badge text-[9px] font-extrabold tracking-wider uppercase px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-400/50 animate-pulse">OFFLINE</span>';
                const pingColor = isOnline ? 'bg-emerald-400' : 'bg-red-400';

                div.className = `board-item board-item-active relative p-3 rounded-lg border-2 ${cardClass} scale-[1.01] transition-all flex items-center justify-between cursor-pointer`;
                div.innerHTML = `
                    <div class="board-accent-bar absolute left-0 top-0 bottom-0 w-1.5 ${barColor} rounded-l-lg"></div>
                    <div class="flex items-center justify-between w-full pl-2">
                        <div class="flex-1 cursor-pointer" onclick="window.deviceHud.updateTargetIp('${board.ip}')">
                            <div class="board-name font-bold text-white flex items-center gap-2">
                                <i data-lucide="hard-drive" class="w-4 h-4 ${iconColor}"></i> <span>${board.id}</span>
                                ${badgeHtml}
                            </div>
                            <div class="board-ip text-xs ${textColor} font-mono mt-1">${board.ip}</div>
                        </div>
                        <div class="flex items-center gap-3">
                            <span class="relative flex h-3 w-3 items-center justify-center">
                                <span class="animate-ping absolute inline-flex h-full w-full rounded-full ${pingColor} opacity-75"></span>
                                <span class="relative inline-flex rounded-full h-2 w-2 ${statusColor} shadow-[0_0_8px_rgba(239,68,68,0.8)]"></span>
                            </span>
                            <button onclick="event.stopPropagation(); window.deviceHud.deleteBoard('${board.ip}')" class="text-slate-500 hover:text-red-400 p-1 rounded hover:bg-slate-700/50 transition-colors" title="Remove Board">
                                <i data-lucide="trash-2" class="w-4 h-4"></i>
                            </button>
                        </div>
                    </div>
                `;
            } else {
                div.className = `board-item p-3 rounded-lg border border-slate-700/70 bg-slate-800/40 hover:bg-slate-800/80 hover:border-slate-600 transition-all flex items-center justify-between cursor-pointer`;
                div.innerHTML = `
                    <div class="flex items-center justify-between w-full">
                        <div class="flex-1 cursor-pointer" onclick="window.deviceHud.updateTargetIp('${board.ip}')">
                            <div class="board-name font-medium text-slate-300 flex items-center gap-2">
                                <i data-lucide="hard-drive" class="w-4 h-4 text-slate-400"></i> <span>${board.id}</span>
                            </div>
                            <div class="board-ip text-xs text-slate-400 font-mono mt-1">${board.ip}</div>
                        </div>
                        <div class="flex items-center gap-3">
                            <div class="w-2 h-2 rounded-full ${statusColor} shadow-[0_0_6px_rgba(0,0,0,0.5)]"></div>
                            <button onclick="event.stopPropagation(); window.deviceHud.deleteBoard('${board.ip}')" class="text-slate-500 hover:text-red-400 p-1 rounded hover:bg-slate-700/50 transition-colors" title="Remove Board">
                                <i data-lucide="trash-2" class="w-4 h-4"></i>
                            </button>
                        </div>
                    </div>
                `;
            }
            
            listEl.appendChild(div);
        });
        
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    deleteBoard(ip) {
        this.boards = this.boards.filter(b => b.ip !== ip);
        localStorage.setItem('gpos_device_boards', JSON.stringify(this.boards));
        if (this.currentIp === ip) {
            this.updateTargetIp(this.boards.length > 0 ? this.boards[0].ip : 'None');
        } else {
            this.renderBoardRegistry();
        }
    }

    updateBoardStatusInRegistry(ip, newStatus) {
        const board = this.boards.find(b => b.ip === ip);
        if (board) {
            board.status = newStatus;
            localStorage.setItem('gpos_device_boards', JSON.stringify(this.boards));
        }
    }

    async updateTargetIp(newIp) {
        this.currentIp = newIp;
        const headerIp = document.getElementById('current-target-ip-display');
        if (headerIp) headerIp.innerText = newIp;
        this.renderBoardRegistry();

        const targetNameEl = document.getElementById('hud-target-name');
        const targetOsEl = document.getElementById('hud-target-os');
        const uptimeEl = document.getElementById('hud-target-uptime');

        this.realCpu = 0;

        if (newIp !== 'None') {
            if (targetNameEl) targetNameEl.innerText = "Querying...";
            if (targetOsEl) targetOsEl.innerText = "--";
            if (uptimeEl) uptimeEl.innerText = "--";

            try {
                const token = localStorage.getItem('auth_token');
                const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
                const response = await fetch(`/api/device/info?ip=${newIp}`, { headers });
                if (response.status === 401) { API.logout(); return; }
                
                if (response.ok) {
                    const data = await response.json();
                    if (data.target === "Unknown Device" || data.os === "Error") {
                        if (targetNameEl) targetNameEl.innerText = "Offline (SSH Failed)";
                        if (targetOsEl) targetOsEl.innerText = "--";
                        if (uptimeEl) uptimeEl.innerText = "--";
                        this.updateBoardStatusInRegistry(newIp, 'offline');
                    } else {
                        if (targetNameEl) targetNameEl.innerText = data.target || "Unknown Board";
                        if (targetOsEl) targetOsEl.innerText = data.os || "webOS";
                        if (uptimeEl) uptimeEl.innerText = data.uptime || "--";
                        if (data.cpu !== undefined) this.realCpu = data.cpu;
                        this.updateBoardStatusInRegistry(newIp, 'online');
                    }
                } else {
                    if (targetNameEl) targetNameEl.innerText = "Offline";
                    this.updateBoardStatusInRegistry(newIp, 'offline');
                }
            } catch (err) {
                console.error("Failed to fetch device info", err);
                if (targetNameEl) targetNameEl.innerText = "Connection Failed";
                this.updateBoardStatusInRegistry(newIp, 'offline');
            }
        } else {
            if (targetNameEl) targetNameEl.innerText = '--';
            if (targetOsEl) targetOsEl.innerText = '--';
            if (uptimeEl) uptimeEl.innerText = '--';
        }
        
        this.renderBoardRegistry();
    }

    startTelemetrySimulation() {
        if (this.telemetryInterval) clearInterval(this.telemetryInterval);
        
        const cpuArc = document.getElementById('cpu-dial-circle');
        const cpuValue = document.getElementById('cpu-dial-value');
        
        this.telemetryInterval = setInterval(() => {
            if (this.currentIp === 'None' || !this.boards.find(b => b.ip === this.currentIp && b.status === 'online')) {
                if(cpuArc) cpuArc.setAttribute('stroke-dasharray', '0, 100');
                if(cpuValue) cpuValue.innerText = '0%';
                return;
            }
            
            let currentCpu = Math.max(0, Math.min(100, this.realCpu || 0));
            let strokeVal = (currentCpu / 100) * 283; 
            
            if(cpuArc) {
                cpuArc.setAttribute('stroke-dasharray', `${strokeVal}, 283`);
                let color = currentCpu > 80 ? '#ef4444' : currentCpu > 50 ? '#f59e0b' : '#10b981';
                cpuArc.setAttribute('stroke', color);
            }
            if(cpuValue) {
                cpuValue.innerText = `${Math.round(currentCpu)}%`;
            }
            
        }, 2000);
    }
    
    renderBenchmark(ipc, cacheMiss, faults, cycles) {
        const container = document.getElementById('performance-graphs-container');
        if (!container) return;
        
        // Calculate abstract scores (0 to 100) for radar chart
        const ipcScore = Math.min(100, (ipc / 2.0) * 100);
        const cacheScore = Math.max(0, 100 - (cacheMiss / 100));
        const memScore = Math.max(0, 100 - (faults / 5));
        
        container.innerHTML = `
            <div class="flex flex-col h-full space-y-4 animate-fade-in w-full">
                <!-- HUD Top Metrics -->
                <div class="grid grid-cols-2 gap-3">
                    <div class="bg-slate-900/80 border border-emerald-500/40 p-3 rounded-lg relative overflow-hidden group shadow-[0_0_15px_rgba(16,185,129,0.15)]">
                        <div class="absolute inset-0 bg-emerald-500/10 transition-colors"></div>
                        <div class="text-[10px] text-emerald-400/80 font-bold uppercase tracking-widest mb-1 z-10 relative">Avg IPC</div>
                        <div class="text-2xl font-black text-white font-mono z-10 relative drop-shadow-lg">${Number(ipc).toFixed(2)}</div>
                    </div>
                    <div class="bg-slate-900/80 border border-amber-500/40 p-3 rounded-lg relative overflow-hidden group shadow-[0_0_15px_rgba(245,158,11,0.15)]">
                        <div class="absolute inset-0 bg-amber-500/10 transition-colors"></div>
                        <div class="text-[10px] text-amber-400/80 font-bold uppercase tracking-widest mb-1 z-10 relative">Cache Miss</div>
                        <div class="text-2xl font-black text-white font-mono z-10 relative drop-shadow-lg">${cacheMiss}</div>
                    </div>
                    <div class="bg-slate-900/80 border border-rose-500/40 p-3 rounded-lg relative overflow-hidden group shadow-[0_0_15px_rgba(244,63,94,0.15)]">
                        <div class="absolute inset-0 bg-rose-500/10 transition-colors"></div>
                        <div class="text-[10px] text-rose-400/80 font-bold uppercase tracking-widest mb-1 z-10 relative">Pg Faults</div>
                        <div class="text-2xl font-black text-white font-mono z-10 relative drop-shadow-lg">${faults}</div>
                    </div>
                    <div class="bg-slate-900/80 border border-blue-500/40 p-3 rounded-lg relative overflow-hidden group shadow-[0_0_15px_rgba(59,130,246,0.15)]">
                        <div class="absolute inset-0 bg-blue-500/10 transition-colors"></div>
                        <div class="text-[10px] text-blue-400/80 font-bold uppercase tracking-widest mb-1 z-10 relative">CPU Cycles</div>
                        <div class="text-xl font-black text-white font-mono z-10 relative drop-shadow-lg">${(cycles/1000000).toFixed(1)}M</div>
                    </div>
                </div>

                <!-- Radar Chart Container -->
                <div class="flex-1 relative bg-slate-900/50 border border-slate-700/50 rounded-lg p-2 min-h-[220px] flex items-center justify-center mt-2 shadow-inner">
                    <canvas id="benchmarkRadarChart"></canvas>
                </div>
            </div>
        `;
        
        // Render Chart.js
        setTimeout(() => {
            const ctx = document.getElementById('benchmarkRadarChart');
            if (ctx && window.Chart) {
                new Chart(ctx, {
                    type: 'radar',
                    data: {
                        labels: ['IPC Eff', 'Cache', 'Memory', 'CPU Load'],
                        datasets: [{
                            label: 'System Profile',
                            data: [ipcScore, cacheScore, memScore, 85],
                            backgroundColor: 'rgba(16, 185, 129, 0.25)',
                            borderColor: 'rgba(16, 185, 129, 1)',
                            pointBackgroundColor: 'rgba(16, 185, 129, 1)',
                            pointBorderColor: '#fff',
                            pointHoverBackgroundColor: '#fff',
                            pointHoverBorderColor: 'rgba(16, 185, 129, 1)',
                            borderWidth: 2,
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            r: {
                                angleLines: { color: 'rgba(255, 255, 255, 0.15)' },
                                grid: { color: 'rgba(255, 255, 255, 0.15)' },
                                pointLabels: { color: 'rgba(148, 163, 184, 1)', font: { size: 11, family: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace', weight: 'bold' } },
                                ticks: { 
                                    display: true, 
                                    min: 0, 
                                    max: 100,
                                    stepSize: 25,
                                    color: 'rgba(16, 185, 129, 0.8)',
                                    backdropColor: 'transparent',
                                    font: { size: 10, family: 'monospace' },
                                    z: 10
                                }
                            }
                        },
                        plugins: {
                            legend: { display: false },
                            datalabels: { display: false }, // Hide the messy overlapping numbers on the dots
                            tooltip: {
                                backgroundColor: 'rgba(15, 23, 42, 0.9)',
                                titleColor: '#10b981',
                                bodyColor: '#f8fafc',
                                borderColor: 'rgba(16, 185, 129, 0.3)',
                                borderWidth: 1
                            }
                        }
                    }
                });
            }
        }, 100);
    }
}

window.deviceHud = new DeviceHUD();

