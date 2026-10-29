const dashboard = {
  charts: {
    burndown: null,
    status: null
  },

  init() {
    this.loadData();
    if (typeof bugWatchdogPanel !== 'undefined' && document.getElementById('bug-watchdog-container')) {
      bugWatchdogPanel.init('bug-watchdog-container');
    }
    setInterval(() => this.loadData(), 60000);
  },

  async loadData() {
    this.showSkeletonLoading();
    try {
      const [reportResult, burndownResult, mentionsResult] = await Promise.allSettled([
        API.getSprintReport(),
        API.getSprintBurndown(),
        API.getMentions()
      ]);

      this.hideSkeletonLoading();

      // 1. Process Sprint Report
      if (reportResult.status === 'fulfilled' && reportResult.value) {
        const report = this.normalizeReport(reportResult.value);
        this.renderKPICards(report);
        this.renderStatusChart(report);
        this.renderDeveloperTable(report);
        this.renderAtRiskPanel(report);

        const sName = report.sprint_name || 'Active Sprint';
        const sprintEl = document.getElementById('sprint-indicator');
        if (sprintEl) {
          sprintEl.textContent = sName;
          sprintEl.title = "Active Sprint: " + sName;
        }

        const connEl = document.getElementById('connection-status');
        if (connEl) {
          connEl.classList.remove('bg-red-500');
          connEl.classList.add('bg-green-500');
        }
      } else {
        const errReason = reportResult.status === 'rejected' ? reportResult.reason : null;
        console.warn("Sprint report request failed or returned empty:", errReason);
        this.renderEmptyReport(errReason ? (errReason.message || String(errReason)) : null);
      }

      // 2. Process Burndown Chart
      if (burndownResult.status === 'fulfilled' && burndownResult.value) {
        const burndown = this.normalizeBurndown(burndownResult.value);
        this.renderBurndownChart(burndown);
      } else {
        console.warn("Burndown request failed:", burndownResult.reason);
        this.renderEmptyBurndown();
      }

      // 3. Process Activity / Mentions
      if (mentionsResult.status === 'fulfilled' && mentionsResult.value) {
        this.renderMentions(mentionsResult.value);
      } else {
        console.warn("Mentions request failed:", mentionsResult.reason);
        this.renderMentions({ mentions: [] });
      }

    } catch (error) {
      console.error("Critical failure in dashboard loadData:", error);
      this.hideSkeletonLoading();
      this.renderEmptyReport("Dashboard load failed. Please refresh or check Settings.");
      const connEl = document.getElementById('connection-status');
      if (connEl) {
        connEl.classList.remove('bg-green-500');
        connEl.classList.add('bg-red-500');
      }
    }
  },

  renderEmptyReport(errorMessage) {
    this.renderKPICards({
      total_issues: 0,
      total_points: 0,
      completed_points: 0,
      completion_percentage: 0,
      at_risk: { total: 0 }
    });
    const sprintEl = document.getElementById('sprint-indicator');
    if (sprintEl) {
      sprintEl.textContent = 'No Active Sprint';
      sprintEl.title = errorMessage || 'No active sprint data found';
    }
    const tbody = document.getElementById('workload-table-body');
    if (tbody) {
      const msg = errorMessage && errorMessage.includes('PAT')
        ? 'Please configure your Jira PAT in Settings (top-right) to view sprint workload.'
        : (errorMessage || 'No sprint issues found for this project.');
      tbody.innerHTML = `<tr><td colspan="8" class="px-5 py-8 text-center text-slate-400">
        <div class="flex flex-col items-center justify-center gap-2">
          <i data-lucide="info" class="w-5 h-5 text-blue-400"></i>
          <span>${msg}</span>
        </div>
      </td></tr>`;
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }
    const container = document.getElementById('at-risk-container');
    if (container) {
      container.innerHTML = '<div class="text-center text-slate-500 py-8 text-xs">No active risk items found.</div>';
    }
    this.renderStatusChart({ status_distribution: { 'Done': 0, 'In Progress': 0, 'To Do': 0 } });
  },

  renderEmptyBurndown() {
    this.renderBurndownChart({
      labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7', 'Day 8', 'Day 9', 'Day 10'],
      ideal: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      actual: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    });
  },

  normalizeReport(raw) {
    if (!raw) return { total_issues: 0, total_points: 0, completed_points: 0, completion_percentage: 0, status_distribution: {}, at_risk: { total: 0 }, workload: [] };
    if (raw.overview) {
      const o = raw.overview;
      const doneTickets = (o.done && o.done.tickets) || 0;
      const ipTickets = (o.in_progress && o.in_progress.tickets) || 0;
      const todoTickets = (o.todo && o.todo.tickets) || 0;
      const donePoints = (o.done && o.done.points) || 0;
      const workload = (raw.developers || []).map(function(d) {
        return {
          developer: d.name,
          username: d.username || '',
          tickets: d.tickets || 0,
          points: d.points || 0,
          done: d.done || 0,
          in_progress: d.in_progress || 0,
          to_do: d.todo || 0,
          progress: d.tickets > 0 ? Math.round((d.done / d.tickets) * 100) : 0,
          non_compliant: d.non_compliant || []
        };
      });
      const atRisk = raw.at_risk || {};
      const unassigned = atRisk.unassigned || [];
      const overdueTickets = atRisk.overdue_tickets || [];
      const blocked = atRisk.blocked || [];
      function mapItem(i) {
        return {
          key: i.key || i,
          summary: i.summary || i,
          url: 'http://jira.lge.com/issue/browse/' + (i.key || i)
        };
      }
      return {
        sprint_name: raw.sprint_name || 'Active Sprint',
        total_issues: o.total_tickets || 0,
        total_points: o.total_points || 0,
        completed_points: donePoints,
        completion_percentage: Math.round(o.completion_pct_points || 0),
        status_distribution: { 'Done': doneTickets, 'In Progress': ipTickets, 'To Do': todoTickets },
        at_risk: {
          total: unassigned.length + overdueTickets.length + blocked.length,
          unassigned: unassigned.map(mapItem),
          overdue_tickets: overdueTickets.map(mapItem),
          blocked: blocked.map(mapItem)
        },
        workload: workload
      };
    }
    return raw;
  },

  normalizeBurndown(raw) {
    if (!raw) return { labels: [], ideal: [], actual: [] };
    if (raw.days && !raw.labels) {
      return { labels: raw.days, ideal: raw.ideal || [], actual: raw.actual || [] };
    }
    return raw;
  },

  showSkeletonLoading() {
    document.querySelectorAll('.kpi-card').forEach(function(el) { el.classList.add('animate-pulse'); });
  },
  hideSkeletonLoading() {
    document.querySelectorAll('.kpi-card').forEach(function(el) { el.classList.remove('animate-pulse'); });
  },

  renderKPICards(data) {
    const total = (data && data.total_issues) || 0;
    const pts = (data && data.completed_points) || 0;
    const comp = (data && data.completion_percentage) || 0;
    const risk = (data && data.at_risk && data.at_risk.total) || 0;
    
    this.animateValue('kpi-total', 0, total, 600);
    this.animateValue('kpi-points', 0, pts, 600);
    this.animateValue('kpi-completion', 0, comp, 600, '%');
    this.animateValue('kpi-risk', 0, risk, 600);
    
    var circle = document.getElementById('kpi-completion-circle');
    if (circle) { 
      circle.style.strokeDasharray = comp + ', 100'; 
    }

    var ptsEl = document.getElementById('kpi-points');
    if (ptsEl && ptsEl.nextElementSibling) {
      ptsEl.nextElementSibling.textContent = `/ ${(data && data.total_points) || 0} total`;
    }
  },

  animateValue(id, start, end, duration, suffix = '') {
    var obj = document.getElementById(id);
    if (!obj) return;
    var target = (typeof end === 'number' && !isNaN(end)) ? end : 0;
    if (target === 0) {
      obj.textContent = '0' + suffix;
      return;
    }
    var startTimestamp = null;
    function step(timestamp) {
      if (!startTimestamp) startTimestamp = timestamp;
      var progress = Math.min((timestamp - startTimestamp) / duration, 1);
      obj.textContent = Math.floor(progress * (target - start) + start) + suffix;
      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        obj.textContent = target + suffix;
      }
    }
    window.requestAnimationFrame(step);
  },

  renderBurndownChart(data) {
    var ctx = document.getElementById('burndownChart');
    if (!ctx) return;
    if (this.charts.burndown) this.charts.burndown.destroy();
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = 'Inter';
    this.charts.burndown = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels || [],
        datasets: [
          {
            label: 'Actual Remaining',
            data: data.actual || [],
            borderColor: '#22c55e',
            backgroundColor: 'rgba(34, 197, 94, 0.08)',
            fill: true, tension: 0.3, borderWidth: 2.5,
            pointBackgroundColor: '#22c55e', pointBorderColor: '#1e293b',
            pointBorderWidth: 2, pointRadius: 4, pointHoverRadius: 6, spanGaps: false
          },
          {
            label: 'Ideal Remaining',
            data: data.ideal || [],
            borderColor: '#3b82f6',
            borderDash: [6, 4],
            fill: false, tension: 0, borderWidth: 2,
            pointRadius: 0, pointHoverRadius: 4, pointBackgroundColor: '#3b82f6'
          }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 6, padding: 10, font: { size: 11 } } },
          tooltip: { backgroundColor: '#1e293b', borderColor: '#334155', borderWidth: 1, titleColor: '#f1f5f9', bodyColor: '#94a3b8', padding: 8, cornerRadius: 6 },
          datalabels: { display: false }
        },
        scales: {
          y: { beginAtZero: true, grid: { color: 'rgba(51, 65, 85, 0.4)', drawBorder: false }, ticks: { padding: 4, font: { size: 11 } } },
          x: { grid: { display: false }, ticks: { padding: 4, font: { size: 11 } } }
        }
      }
    });
  },

  renderStatusChart(data) {
    var ctx = document.getElementById('statusChart');
    if (!ctx) return;
    if (this.charts.status) this.charts.status.destroy();
    var dist = (data && data.status_distribution) || {};
    
    // Register datalabels globally if available
    if (typeof ChartDataLabels !== 'undefined') {
        Chart.register(ChartDataLabels);
    }

    const doneCount = dist['Done'] || 0;
    const ipCount = dist['In Progress'] || 0;
    const todoCount = dist['To Do'] || 0;
    const totalCount = doneCount + ipCount + todoCount;

    const chartLabels = totalCount === 0 ? ['No Tickets'] : ['Done', 'In Progress', 'To Do'];
    const chartData = totalCount === 0 ? [1] : [doneCount, ipCount, todoCount];
    const chartColors = totalCount === 0 ? ['#334155'] : ['#22c55e', '#f59e0b', '#475569'];
    
    this.charts.status = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: chartLabels,
        datasets: [{ 
          data: chartData, 
          backgroundColor: chartColors, 
          borderColor: '#1e293b', 
          borderWidth: 2, 
          hoverOffset: 4 
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        aspectRatio: 1,
        cutout: '68%',
        plugins: {
          legend: { 
            position: 'bottom', 
            labels: { usePointStyle: true, boxWidth: 6, padding: 8, font: { size: 11 } } 
          },
          tooltip: { 
            backgroundColor: '#1e293b', borderColor: '#334155', borderWidth: 1, 
            titleColor: '#f1f5f9', bodyColor: '#94a3b8', padding: 8, cornerRadius: 6,
            callbacks: {
              label: function(context) {
                if (totalCount === 0) return ' No tickets found';
                return ` ${context.label}: ${context.raw}`;
              }
            }
          },
          datalabels: {
            color: '#ffffff',
            font: { weight: 'bold', size: 11 },
            formatter: (value, ctx) => {
              if (totalCount === 0 || value === 0) return '';
              let percentage = (value * 100 / totalCount).toFixed(0) + "%";
              return percentage;
            }
          }
        }
      }
    });
  },

  renderDeveloperTable(data) {
    var tbody = document.getElementById('workload-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    const workload = (data && data.workload) || [];
    if (workload.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="px-5 py-8 text-center text-slate-400">No developer workload data found for this sprint.</td></tr>';
      return;
    }
    workload.forEach(function(dev) {
      var row = document.createElement('tr');
      row.className = 'hover:bg-slate-800/50 transition-colors';
      var barColor = dev.progress >= 80 ? 'bg-green-500' : (dev.progress >= 40 ? 'bg-blue-500' : 'bg-amber-500');
      
      // Build non-compliant issues tooltip string
      var ncHtml = '-';
      if (dev.non_compliant && dev.non_compliant.length > 0) {
        var tooltipItems = dev.non_compliant.map(function(nc) {
           return nc.key + ' (' + (nc.missing || []).join(', ') + ')';
        }).join('&#10;');
        ncHtml = '<div class="inline-flex items-center justify-center min-w-[1.5rem] text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded cursor-help border border-red-500/30 font-bold whitespace-nowrap" title="' + tooltipItems + '">' + dev.non_compliant.length + '</div>';
      }
      
      var uname = dev.username || dev.developer;
      row.innerHTML = '<td class="px-5 py-3 text-blue-400 font-medium cursor-pointer hover:underline" onclick="window.searchUserTickets(\'' + uname.replace(/'/g, "\\'") + '\')">' + dev.developer + '</td>' +
        '<td class="px-5 py-3 text-blue-400 font-medium text-right cursor-pointer hover:underline" onclick="window.searchUserTickets(\'' + uname.replace(/'/g, "\\'") + '\')">' + dev.tickets + '</td>' +
        '<td class="px-5 py-3 text-slate-300 text-right">' + dev.points + '</td>' +
        '<td class="px-5 py-3 text-center"><span class="badge badge-done cursor-pointer hover:opacity-80" onclick="window.searchUserTickets(\'' + uname.replace(/'/g, "\\'") + '\', \'Done\')">' + dev.done + '</span></td>' +
        '<td class="px-5 py-3 text-center"><span class="badge badge-in-progress cursor-pointer hover:opacity-80" onclick="window.searchUserTickets(\'' + uname.replace(/'/g, "\\'") + '\', \'In Progress\')">' + dev.in_progress + '</span></td>' +
        '<td class="px-5 py-3 text-center"><span class="badge badge-todo cursor-pointer hover:opacity-80" onclick="window.searchUserTickets(\'' + uname.replace(/'/g, "\\'") + '\', \'To Do\')">' + dev.to_do + '</span></td>' +
        '<td class="px-5 py-3 text-center">' + ncHtml + '</td>' +
        '<td class="px-5 py-3"><div class="flex items-center gap-2"><div class="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden"><div class="h-full rounded-full transition-all duration-700 ease-out ' + barColor + '" style="width: ' + dev.progress + '%"></div></div><span class="text-xs text-slate-400 w-8 text-right">' + dev.progress + '%</span></div></td>';
      tbody.appendChild(row);
    });
  },

  renderAtRiskPanel(data) {
    var container = document.getElementById('at-risk-container');
    if (!container) return;
    container.innerHTML = '';
    var sections = [
      { title: 'Unassigned Tickets', items: (data.at_risk && data.at_risk.unassigned) || [], icon: 'user-x', color: 'text-slate-400' },
      { title: 'Overdue Tickets', items: (data.at_risk && data.at_risk.overdue_tickets) || [], icon: 'clock', color: 'text-amber-400' },
      { title: 'Blocked Tickets', items: (data.at_risk && data.at_risk.blocked) || [], icon: 'ban', color: 'text-red-400' }
    ];
    sections.forEach(function(sec) {
      if (!sec.items) sec.items = [];
      var el = document.createElement('div');
      el.className = 'bg-slate-900/50 border border-slate-700/50 rounded-lg overflow-hidden';
      var header = document.createElement('button');
      header.className = 'w-full px-4 py-3 flex items-center justify-between hover:bg-slate-800/80 transition-colors focus:outline-none';
      header.innerHTML = '<div class="flex items-center gap-2"><i data-lucide="' + sec.icon + '" class="w-4 h-4 ' + sec.color + '"></i><span class="text-sm font-medium text-slate-200">' + sec.title + '</span><span class="bg-slate-800 text-slate-400 text-xs px-2 py-0.5 rounded-full border border-slate-700">' + sec.items.length + '</span></div><i data-lucide="chevron-down" class="w-4 h-4 text-slate-500 transition-transform"></i>';
      var content = document.createElement('div');
      content.className = 'px-4 pb-3 space-y-2';
        if (sec.items.length === 0) {
            content.innerHTML = `<div class="text-xs text-slate-500 italic py-2">No ${sec.title.toLowerCase()}</div>`;
        }
      sec.items.forEach(function(item) {
        var ticket = document.createElement('a');
        ticket.href = item.url || '#';
        ticket.target = '_blank';
        ticket.className = 'block p-3 bg-slate-800 border border-slate-700 rounded-md hover:border-blue-500/50 transition-colors group cursor-pointer';
        ticket.innerHTML = '<div class="flex items-start gap-3"><span class="text-xs font-semibold text-blue-400 group-hover:text-blue-300 mt-0.5 shrink-0">' + item.key + '</span><span class="text-sm text-slate-300 group-hover:text-slate-200 line-clamp-1">' + item.summary + '</span></div>';
        content.appendChild(ticket);
      });
      header.addEventListener('click', function() {
        content.classList.toggle('hidden');
      });
      el.appendChild(header);
      el.appendChild(content);
      container.appendChild(el);
    });
    if (typeof lucide !== 'undefined') lucide.createIcons();
  },

  renderMentions(data) {
    const container = document.getElementById('activity-stream-container');
    if (!container) return;
    
    container.innerHTML = '';
    const mentions = data.mentions || [];
    
    if (mentions.length === 0) {
      container.innerHTML = '<div class="text-center text-slate-500 py-8 text-sm">No recent mentions or assigned tickets found.</div>';
      return;
    }
    
    const list = document.createElement('div');
    list.className = 'divide-y divide-slate-700/50';
    
    mentions.forEach(item => {
      const el = document.createElement('a');
      el.href = item.url || '#';
      el.target = '_blank';
      el.className = 'flex items-start gap-4 p-4 hover:bg-slate-700/30 transition-colors group cursor-pointer';
      
      const iconWrap = document.createElement('div');
      iconWrap.className = 'w-8 h-8 rounded-full bg-blue-500/20 text-blue-400 flex flex-shrink-0 items-center justify-center mt-1 border border-blue-500/30 group-hover:bg-blue-500/30 transition-colors';
      iconWrap.innerHTML = '<i data-lucide="at-sign" class="w-4 h-4"></i>';
      
      const content = document.createElement('div');
      content.className = 'flex-1 min-w-0';
      
      const header = document.createElement('div');
      header.className = 'flex items-baseline justify-between gap-2';
      header.innerHTML = `
        <span class="text-sm font-semibold text-blue-400 group-hover:text-blue-300 transition-colors">${item.key}</span>
        <span class="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">${item.status}</span>
      `;
      
      const summary = document.createElement('p');
      summary.className = 'text-sm text-slate-300 mt-1 line-clamp-2 group-hover:text-slate-200 transition-colors';
      summary.textContent = item.summary;
      
      content.appendChild(header);
      content.appendChild(summary);
      
      el.appendChild(iconWrap);
      el.appendChild(content);
      list.appendChild(el);
    });
    
    container.appendChild(list);
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
};


// ─── Bug Watchdog Panel ───────────────────────────────────────────────────────
const bugWatchdogPanel = {
  _timer: null,

  PRIORITY_COLORS: {
    p1: 'bg-red-500/20 text-red-400 border-red-500/40',
    p2: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    p3: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    p4: 'bg-slate-600/20 text-slate-400 border-slate-500/40',
    blocker:  'bg-red-500/20 text-red-400 border-red-500/40',
    critical: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    major:    'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    minor:    'bg-slate-600/20 text-slate-400 border-slate-500/40',
  },

  ACTION_COLORS: {
    'REMINDED':      'bg-amber-500/20 text-amber-400 border-amber-500/40',
    'LABEL_UPDATED': 'bg-blue-500/20 text-blue-400 border-blue-500/40',
    'ANALYSIS_DONE': 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
  },

  init(containerId) {
    this.containerId = containerId;
    this.load();
    this._timer = setInterval(() => this.load(), 60000);
  },

  destroy() {
    if (this._timer) clearInterval(this._timer);
  },

  async load() {
    const container = document.getElementById(this.containerId);
    if (!container) return;
    try {
      const token = localStorage.getItem('auth_token') || localStorage.getItem('ax_portal_token') || '';
      const resp  = await fetch('/api/watchdog/bug-status', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      this.render(container, data);
    } catch (err) {
      container.innerHTML = `<div class="text-xs text-red-400 p-3">Failed to load watchdog status: ${err.message}</div>`;
    }
  },

  async reset() {
    const token = localStorage.getItem('auth_token') || localStorage.getItem('ax_portal_token') || '';
    await fetch('/api/watchdog/bug-status/reset', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    this.load();
  },

  _priorityBadge(priority) {
    const key   = (priority || 'unknown').toLowerCase();
    const color = this.PRIORITY_COLORS[key] || 'bg-slate-600/20 text-slate-400 border-slate-500/40';
    return `<span class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${color}">${priority || '—'}</span>`;
  },

  _actionBadge(action) {
    const color = this.ACTION_COLORS[action] || 'bg-slate-600/20 text-slate-400 border-slate-500/40';
    return `<span class="text-[10px] font-medium px-2 py-0.5 rounded border ${color}">${action || '—'}</span>`;
  },

  render(container, data) {
    const enabled     = data.enabled;
    const users       = (data.watched_users || []).join(', ') || 'None';
    const project     = data.project || '—';
    const interval    = data.interval_s ? `${data.interval_s}s` : '—';
    const remindHours = data.remind_hours ? `${data.remind_hours}h` : '—';
    const entries     = data.recent_entries || data.in_memory_log || [];

    const rows = entries.map(e => `
      <tr class="border-b border-slate-800 hover:bg-slate-800/40 transition-colors">
        <td class="px-3 py-2 font-mono text-blue-400 text-xs font-semibold">${e.issue_key || '—'}</td>
        <td class="px-3 py-2">${this._priorityBadge(e.priority)}</td>
        <td class="px-3 py-2">${e.prereq_ok
          ? '<span class="text-[10px] text-emerald-400 font-semibold">✅ PASS</span>'
          : '<span class="text-[10px] text-red-400 font-semibold">❌ FAIL</span>'}</td>
        <td class="px-3 py-2">${this._actionBadge(e.action)}</td>
        <td class="px-3 py-2 text-[11px] text-slate-400 max-w-xs truncate" title="${e.missing_items || ''}">${e.missing_items || '—'}</td>
        <td class="px-3 py-2">${e.analysis_ok
          ? '<span class="text-[10px] text-emerald-400 font-semibold">✅ Done</span>'
          : '<span class="text-[10px] text-slate-500">—</span>'}</td>
        <td class="px-3 py-2 text-[10px] text-slate-500 font-mono whitespace-nowrap">${(e.cycle_at || e.reminded_at || '').substring(0,16).replace('T',' ')}</td>
      </tr>`).join('');

    container.innerHTML = `
      <div class="bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
        <div class="flex items-center justify-between px-4 py-3 bg-slate-800/80 border-b border-slate-700">
          <div class="flex items-center gap-2.5">
            <div class="p-1.5 rounded-lg ${enabled ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-slate-700/60 border border-slate-600'}">
              <i data-lucide="shield-check" class="w-4 h-4 ${enabled ? 'text-emerald-400' : 'text-slate-500'}"></i>
            </div>
            <div>
              <h3 class="text-sm font-bold text-slate-100">Bug Watchdog v2</h3>
              <p class="text-[10px] text-slate-400">${project} · poll every ${interval} · re-remind every ${remindHours}</p>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span class="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-semibold
              ${enabled ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-slate-700 border-slate-600 text-slate-400'}">
              <span class="w-1.5 h-1.5 rounded-full ${enabled ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}"></span>
              ${enabled ? 'Active' : 'Disabled'}
            </span>
            <button onclick="bugWatchdogPanel.load()"
              class="p-1.5 rounded-md bg-slate-700 hover:bg-slate-600 text-slate-400 hover:text-slate-200 transition-colors border border-slate-600" title="Refresh">
              <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
            </button>
            <button onclick="bugWatchdogPanel.reset()"
              class="p-1.5 rounded-md bg-slate-700 hover:bg-slate-600 text-slate-400 hover:text-slate-200 transition-colors border border-slate-600" title="Clear in-memory log">
              <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </div>
        <div class="px-4 py-2 bg-slate-800/40 border-b border-slate-700/60 flex items-center gap-2">
          <i data-lucide="users" class="w-3.5 h-3.5 text-blue-400 flex-shrink-0"></i>
          <span class="text-[11px] text-slate-400">Watched:</span>
          <span class="text-[11px] text-slate-200 font-mono">${users}</span>
        </div>
        ${entries.length === 0 ? `
          <div class="px-4 py-8 text-center text-slate-500 text-sm">
            <i data-lucide="inbox" class="w-8 h-8 mx-auto mb-2 opacity-40"></i>
            No bugs processed yet this session.
          </div>` : `
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-left">
              <thead class="text-[10px] uppercase text-slate-400 bg-slate-900/60 border-b border-slate-700">
                <tr>
                  <th class="px-3 py-2">Bug Key</th>
                  <th class="px-3 py-2">Priority</th>
                  <th class="px-3 py-2">Prereqs</th>
                  <th class="px-3 py-2">Action</th>
                  <th class="px-3 py-2">Missing Items</th>
                  <th class="px-3 py-2">Analysis</th>
                  <th class="px-3 py-2">Cycle Time</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60">${rows}</tbody>
            </table>
          </div>`}
      </div>`;

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
};
