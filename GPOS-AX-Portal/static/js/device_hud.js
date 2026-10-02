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
        this.isInitialized = true;
    }

    async pingAllBoards() {
        // Run a quick check on all registered boards to update their status dots
        for (let board of this.boards) {
            try {
                const token = localStorage.getItem('auth_token');
                const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
                const response = await fetch(`/api/device/info?ip=${board.ip}`, { headers });
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
            
            div.className = `p-3 rounded-lg border flex items-center justify-between transition-colors ${isActive ? 'bg-slate-800 border-emerald-500/50' : 'bg-slate-800/50 border-slate-700 hover:border-slate-500'}`;
            
            div.innerHTML = `
                <div class="flex items-center justify-between w-full">
                    <div class="flex-1 cursor-pointer" onclick="window.deviceHud.updateTargetIp('${board.ip}')">
                        <div class="font-medium text-slate-200 flex items-center gap-2">
                            <i data-lucide="hard-drive" class="w-4 h-4"></i> ${board.id}
                        </div>
                        <div class="text-xs text-slate-400 mt-1">${board.ip}</div>
                    </div>
                    <div class="flex items-center gap-3">
                        <div class="w-2 h-2 rounded-full ${statusColor} shadow-[0_0_8px_rgba(16,185,129,0.4)]"></div>
                        <button onclick="event.stopPropagation(); window.deviceHud.deleteBoard('${board.ip}')" class="text-slate-500 hover:text-red-400 p-1 rounded hover:bg-slate-700/50 transition-colors" title="Remove Board">
                            <i data-lucide="trash-2" class="w-4 h-4"></i>
                        </button>
                    </div>
                </div>
            `;
            
            listEl.appendChild(div);
        });
        
        if(typeof lucide !== 'undefined') lucide.createIcons();
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
        const container = document.getElementById('performance-analytics-container');
        if (!container) return;
        
        const missScore = Math.min(100, cacheMiss / 500);
        const faultScore = Math.min(100, faults / 10);
        
        container.innerHTML = `
            <div class="space-y-4 w-full text-xs">
                <div>
                    <div class="flex justify-between text-slate-300 mb-1">
                        <span>Instructions / Cycle (IPC)</span>
                        <span class="font-mono text-emerald-400">${ipc}</span>
                    </div>
                    <div class="w-full bg-slate-700 h-1.5 rounded-full overflow-hidden">
                        <div class="bg-emerald-500 h-full rounded-full" style="width: ${Math.min(100, ipc*30)}%"></div>
                    </div>
                </div>
                <div>
                    <div class="flex justify-between text-slate-300 mb-1">
                        <span>Cache Misses</span>
                        <span class="font-mono text-amber-400">${cacheMiss}</span>
                    </div>
                    <div class="w-full bg-slate-700 h-1.5 rounded-full overflow-hidden">
                        <div class="bg-amber-500 h-full rounded-full" style="width: ${missScore}%"></div>
                    </div>
                </div>
                <div>
                    <div class="flex justify-between text-slate-300 mb-1">
                        <span>Page Faults</span>
                        <span class="font-mono text-red-400">${faults}</span>
                    </div>
                    <div class="w-full bg-slate-700 h-1.5 rounded-full overflow-hidden">
                        <div class="bg-red-500 h-full rounded-full" style="width: ${faultScore}%"></div>
                    </div>
                </div>
                <div class="pt-2 mt-2 border-t border-slate-700/50 flex justify-between items-center">
                    <span class="text-slate-400">Total CPU Cycles</span>
                    <span class="font-mono text-slate-200">${cycles.toLocaleString()}</span>
                </div>
            </div>
        `;
    }
}

window.deviceHud = new DeviceHUD();
