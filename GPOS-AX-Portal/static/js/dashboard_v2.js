const dashboard = {
  charts: {
    burndown: null,
    status: null
  },

  init() {
    this.loadData();
    setInterval(() => this.loadData(), 60000);
  },

  async loadData() {
    this.showSkeletonLoading();
    try {
      const [reportRaw, burndownRaw, mentionsRaw] = await Promise.all([
        API.getSprintReport(),
        API.getSprintBurndown(),
        API.getMentions()
      ]);
      const report = this.normalizeReport(reportRaw);
      const burndown = this.normalizeBurndown(burndownRaw);
      this.hideSkeletonLoading();
      this.renderKPICards(report);
      this.renderBurndownChart(burndown);
      this.renderStatusChart(report);
      this.renderDeveloperTable(report);
      this.renderAtRiskPanel(report);
      this.renderMentions(mentionsRaw);
      document.getElementById('sprint-indicator').textContent = report.sprint_name + ' Active';
      document.getElementById('connection-status').classList.remove('bg-red-500');
      document.getElementById('connection-status').classList.add('bg-green-500');
    } catch (error) {
      console.error("Failed to load dashboard data", error);
      document.getElementById('connection-status').classList.remove('bg-green-500');
      document.getElementById('connection-status').classList.add('bg-red-500');
    }
  },

  normalizeReport(raw) {
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
          tickets: d.tickets,
          points: d.points,
          done: d.done || 0,
          in_progress: d.in_progress || 0,
          to_do: d.todo || 0,
          progress: d.tickets > 0 ? Math.round((d.done / d.tickets) * 100) : 0,
          non_compliant: d.non_compliant || []
        };
      });
      const atRisk = raw.at_risk || {};
      const unassigned = atRisk.unassigned || [];
      const overdueTickets = atRisk.overdue_tickets || atRisk.overdue_tickets || [];
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
        total_issues: o.total_tickets,
        total_points: o.total_points,
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
    if (raw.days && !raw.labels) {
      return { labels: raw.days, ideal: raw.ideal, actual: raw.actual };
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
    this.animateValue('kpi-total', 0, data.total_issues, 1000);
    this.animateValue('kpi-points', 0, data.completed_points, 1000);
    this.animateValue('kpi-completion', 0, data.completion_percentage, 1000);
    this.animateValue('kpi-risk', 0, (data.at_risk && data.at_risk.total) || 0, 1000);
    var circle = document.getElementById('kpi-completion-circle');
    if (circle) { circle.style.strokeDasharray = data.completion_percentage + ', 100'; }
  },

  animateValue(id, start, end, duration) {
    var obj = document.getElementById(id);
    if (!obj) return;
    var startTimestamp = null;
    function step(timestamp) {
      if (!startTimestamp) startTimestamp = timestamp;
      var progress = Math.min((timestamp - startTimestamp) / duration, 1);
      obj.innerHTML = Math.floor(progress * (end - start) + start);
      if (progress < 1) window.requestAnimationFrame(step);
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
        labels: data.labels,
        datasets: [
          {
            label: 'Actual Remaining',
            data: data.actual,
            borderColor: '#22c55e',
            backgroundColor: 'rgba(34, 197, 94, 0.08)',
            fill: true, tension: 0.3, borderWidth: 2.5,
            pointBackgroundColor: '#22c55e', pointBorderColor: '#1e293b',
            pointBorderWidth: 2, pointRadius: 4, pointHoverRadius: 6, spanGaps: false
          },
          {
            label: 'Ideal Remaining',
            data: data.ideal,
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
          legend: { position: 'bottom', labels: { usePointStyle: true, padding: 16, font: { size: 12 } } },
          tooltip: { backgroundColor: '#1e293b', borderColor: '#334155', borderWidth: 1, titleColor: '#f1f5f9', bodyColor: '#94a3b8', padding: 12, cornerRadius: 8 },
          datalabels: { display: false }
        },
        scales: {
          y: { beginAtZero: true, grid: { color: 'rgba(51, 65, 85, 0.5)', drawBorder: false }, ticks: { padding: 8 } },
          x: { grid: { display: false }, ticks: { padding: 8 } }
        }
      }
    });
  },

  renderStatusChart(data) {
    var ctx = document.getElementById('statusChart');
    if (!ctx) return;
    if (this.charts.status) this.charts.status.destroy();
    var dist = data.status_distribution;
    
    // Register datalabels globally if available
    if (typeof ChartDataLabels !== 'undefined') {
        Chart.register(ChartDataLabels);
    }
    
    this.charts.status = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Done', 'In Progress', 'To Do'],
        datasets: [{ data: [dist['Done'] || 0, dist['In Progress'] || 0, dist['To Do'] || 0], backgroundColor: ['#22c55e', '#f59e0b', '#475569'], borderColor: '#1e293b', borderWidth: 3, hoverOffset: 6 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '72%',
        plugins: {
          legend: { position: 'bottom', labels: { usePointStyle: true, padding: 16, font: { size: 12 } } },
          tooltip: { backgroundColor: '#1e293b', borderColor: '#334155', borderWidth: 1, titleColor: '#f1f5f9', bodyColor: '#94a3b8', padding: 12, cornerRadius: 8 },
          datalabels: {
            color: '#ffffff',
            font: { weight: 'bold', size: 14 },
            formatter: (value, ctx) => {
              if (value === 0) return '';
              let sum = 0;
              let dataArr = ctx.chart.data.datasets[0].data;
              dataArr.map(data => { sum += data; });
              let percentage = (value * 100 / sum).toFixed(0) + "%";
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
    (data.workload || []).forEach(function(dev) {
      var row = document.createElement('tr');
      row.className = 'hover:bg-slate-800/50 transition-colors';
      var barColor = dev.progress >= 80 ? 'bg-green-500' : (dev.progress >= 40 ? 'bg-blue-500' : 'bg-amber-500');
      
      // Build non-compliant issues tooltip string
      var ncHtml = '-';
      if (dev.non_compliant && dev.non_compliant.length > 0) {
        var tooltipItems = dev.non_compliant.map(function(nc) {
           return nc.key + ' (' + nc.missing.join(', ') + ')';
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
      container.innerHTML = '<div class="text-center text-slate-500 py-8 text-sm">No mentions found today.</div>';
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
