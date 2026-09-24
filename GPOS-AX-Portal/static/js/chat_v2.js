window.chat = {
  init() {
    this.form = document.getElementById('chat-form');
    this.input = document.getElementById('chat-input');
    this.messagesContainer = document.getElementById('chat-messages');

    // Auto-resize textarea
    this.input.addEventListener('input', function() {
      this.style.height = 'auto';
      this.style.height = (this.scrollHeight) + 'px';
    });

    this.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.handleSendMessage();
      }
    });

    this.form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (this.abortController) {
        this.abortController.abort();
        return;
      }
      this.handleSendMessage();
    });

    // Quick Actions
    document.querySelectorAll('.quick-action-chip').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const action = e.currentTarget.dataset.action;
        const text = e.currentTarget.textContent.trim();
        this.handleSendMessage(action, text);
      });
    });
  },

  currentAgentId: 'jira-agent',
  messageHistory: [],

  saveHistory() {
    if (!this.messagesContainer) return;
    localStorage.setItem(`chat_html_${this.currentAgentId}`, this.messagesContainer.innerHTML);
    localStorage.setItem(`chat_history_${this.currentAgentId}`, JSON.stringify(this.messageHistory));
  },

  loadHistory(agentId) {
    // If switching to the same agent and we already have messages, keep them (preserves state when switching to Dashboard and back)
    if (this.currentAgentId === agentId && this.messageHistory && this.messageHistory.length > 0) {
        return;
    }
    
    this.currentAgentId = agentId;
    this.messageHistory = [];
    this.clear();
  },
  
  createNewSession() {
    if (this.messageHistory.length > 0) {
        let sessions = JSON.parse(localStorage.getItem(`sessions_${this.currentAgentId}`) || '[]');
        sessions.push({
            id: Date.now().toString(),
            date: new Date().toLocaleString(),
            html: this.messagesContainer.innerHTML,
            history: this.messageHistory,
            summary: this.messageHistory[0]?.content?.substring(0, 50) + "..." || "New Chat"
        });
        localStorage.setItem(`sessions_${this.currentAgentId}`, JSON.stringify(sessions));
    }
    this.clear();
    this.saveHistory();
  },
  
  showHistoryModal() {
      const modal = document.getElementById('history-modal');
      const list = document.getElementById('history-list');
      if (!modal || !list) return;
      
      let sessions = JSON.parse(localStorage.getItem(`sessions_${this.currentAgentId}`) || '[]');
      
      if (sessions.length === 0) {
          list.innerHTML = '<div class="text-slate-400 text-sm text-center py-4">No past sessions found for this agent.</div>';
      } else {
          list.innerHTML = sessions.sort((a,b) => b.id - a.id).map(s => `
              <div class="p-3 bg-slate-900/50 border border-slate-700 rounded-lg hover:border-blue-500/50 cursor-pointer transition-colors" onclick="window.chat.loadSession('${s.id}')">
                  <div class="text-sm text-slate-200 font-medium mb-1">${s.summary}</div>
                  <div class="text-xs text-slate-500">${s.date} • ${s.history.length} messages</div>
              </div>
          `).join('');
      }
      
      modal.classList.remove('hidden');
      modal.classList.add('flex');
  },
  
  loadSession(id) {
      let sessions = JSON.parse(localStorage.getItem(`sessions_${this.currentAgentId}`) || '[]');
      let s = sessions.find(x => x.id === id);
      if (s) {
          // Push current to history if not empty
          this.createNewSession();
          
          this.messageHistory = s.history;
          this.messagesContainer.innerHTML = s.html;
          this.saveHistory();
          
          // Remove from sessions list since it's active now
          sessions = sessions.filter(x => x.id !== id);
          localStorage.setItem(`sessions_${this.currentAgentId}`, JSON.stringify(sessions));
          
          if (typeof lucide !== 'undefined') lucide.createIcons();
          if (typeof mermaid !== 'undefined') {
              try { mermaid.run({ nodes: this.messagesContainer.querySelectorAll('.mermaid') }); } catch (e) {}
          }
          this.scrollToBottom();
          
          const modal = document.getElementById('history-modal');
          if (modal) {
              modal.classList.add('hidden');
              modal.classList.remove('flex');
          }
      }
  },

  clear() {
    this.messageHistory = [];
    
    // Update the header title based on current agent
    const agents = {
        'jira-agent': { name: 'GPOS Jira & Governance Agent', desc: 'Ask about sprint health, blockages, or auto-grooming' },
        'design-agent': { name: 'GPOS HLD Design Studio', desc: 'Generates High-Level Designs and architecture specs' }
    };
    
    const currentInfo = agents[this.currentAgentId] || agents['jira-agent'];
    const titleEl = document.getElementById('chat-agent-title');
    const descEl = document.getElementById('chat-agent-desc');
    if (titleEl) titleEl.textContent = currentInfo.name;
    if (descEl) descEl.textContent = currentInfo.desc;

    if (this.messagesContainer) {
      this.messagesContainer.innerHTML = `
        <!-- Initial Greeting -->
        <div class="flex gap-4">
            <div class="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center flex-shrink-0">
                <i data-lucide="bot" class="w-4 h-4 text-white"></i>
            </div>
            <div class="bg-slate-700 rounded-2xl rounded-tl-none px-4 py-3 max-w-[85%] text-sm text-slate-200">
                <p class="mb-2">Hello! I'm connected to the GPOS project.</p>
                <p>Here are some things you can ask me:</p>
                                  <div class="flex flex-wrap gap-2 mt-3">
                      <button onclick="document.getElementById('chat-input').value='Generate sprint report'; document.getElementById('chat-form').dispatchEvent(new Event('submit'));" class="px-3 py-1.5 rounded-full bg-slate-800 border border-slate-600 text-xs hover:bg-slate-600 transition-colors flex items-center gap-1"><i data-lucide="bar-chart-2" class="w-3 h-3"></i>Generate sprint report</button>
                      <button onclick="document.getElementById('chat-input').value='Show burndown status'; document.getElementById('chat-form').dispatchEvent(new Event('submit'));" class="px-3 py-1.5 rounded-full bg-slate-800 border border-slate-600 text-xs hover:bg-slate-600 transition-colors flex items-center gap-1"><i data-lucide="trending-down" class="w-3 h-3"></i>Show burndown status</button>
                      <button onclick="document.getElementById('chat-input').value='Audit unassigned tickets'; document.getElementById('chat-form').dispatchEvent(new Event('submit'));" class="px-3 py-1.5 rounded-full bg-slate-800 border border-slate-600 text-xs hover:bg-slate-600 transition-colors flex items-center gap-1"><i data-lucide="shield-check" class="w-3 h-3"></i>Audit unassigned tickets</button>
                      <button onclick="document.getElementById('chat-input').value='Weekly Status'; document.getElementById('chat-form').dispatchEvent(new Event('submit'));" class="px-3 py-1.5 rounded-full bg-slate-800 border border-purple-500/50 text-purple-400 text-xs hover:bg-slate-700 transition-colors flex items-center gap-1"><i data-lucide="calendar-days" class="w-3 h-3"></i>Weekly Status</button>
                      <button onclick="document.getElementById('chat-input').value='Weekly status for all'; document.getElementById('chat-form').dispatchEvent(new Event('submit'));" class="px-3 py-1.5 rounded-full bg-slate-800 border border-blue-500/50 text-blue-400 text-xs hover:bg-slate-700 transition-colors flex items-center gap-1"><i data-lucide="users" class="w-3 h-3"></i>Weekly status for all</button>
                      <button onclick="document.getElementById('chat-input').value='I want to create a new story. Please guide me and ask me to provide the Summary, Story Points, Description, Assignee, Label, and Sprint one by one.'; document.getElementById('chat-form').dispatchEvent(new Event('submit'));" class="px-3 py-1.5 rounded-full bg-slate-800 border border-blue-500/50 text-blue-400 text-xs hover:bg-slate-700 transition-colors flex items-center gap-1"><i data-lucide="plus-circle" class="w-3 h-3"></i>Create new story</button>
                  </div>
            </div>
        </div>
      `;
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
      // Do not save history here, it's just a fallback. Actually, yes, let's clear it from local storage if called.
      // Wait, clear() is called to initialize default state. If we call saveHistory(), it overwrites history with default state.
      // Oh, `clear()` should only be called if there's NO history.
      // Let's just return.
    }
  },

  async handleSendMessage(forcedAction = null, label = null) {
    if (this.abortController) return;
    const text = (forcedAction ? label : this.input.value).trim();
    if (!text && !forcedAction) return;

    if (!forcedAction) {
      this.input.value = '';
      this.input.style.height = 'auto';
    }

    // Add user message bubble
    this.addMessage(text, 'user');

    // Show loading spinner
    const loadingId = this.showLoading();

    this.abortController = new AbortController();
    const submitBtn = document.getElementById('chat-submit-btn');
    if (submitBtn) {
        submitBtn.classList.replace('bg-blue-600', 'bg-red-600');
        submitBtn.classList.replace('hover:bg-blue-500', 'hover:bg-red-500');
        submitBtn.innerHTML = '<i data-lucide="square" class="w-4 h-4 fill-current"></i>';
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    try {
        const llmUrl = localStorage.getItem('llm_api_url');
        const llmKey = localStorage.getItem('llm_api_key');
        const llmModel = localStorage.getItem('llm_api_model') || 'Chat-EXACODE-A';
        
        if (llmUrl && llmKey) {
            // Add user message to history IMMEDIATELY so tab switching doesn't wipe the chat
            this.messageHistory.push({ role: 'user', content: text });
            
            // Fast interception for specific quick actions
            let llmResp;
            if (text.toLowerCase().includes('weekly status')) {
                const pat = localStorage.getItem('jira_pat') || '';
                const resp = await fetch('/api/weekly_status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Jira-PAT': pat },
                    body: JSON.stringify({ message: text, llm_url: llmUrl, llm_key: llmKey, llm_model: llmModel }),
                    signal: this.abortController.signal
                });
                if (!resp.ok) {
                    const errTxt = await resp.text();
                    throw new Error("Weekly Status API Failed: " + errTxt);
                }
                llmResp = await resp.json();              } else if (text.toLowerCase().includes('burndown')) {
                  const pat = localStorage.getItem('jira_pat') || '';
                  const resp = await fetch('/api/sprint/burndown', {
                      headers: { 'X-Jira-PAT': pat },
                      signal: this.abortController.signal
                  });
                  if (!resp.ok) throw new Error("Burndown API Failed: " + resp.statusText);
                  const data = await resp.json();
                  this.removeLoading(loadingId);
                  this.addAgentCard(data, 'burndown');
                  return;
              } else if (text.toLowerCase().includes('audit unassigned tickets')) {
                const pat = localStorage.getItem('jira_pat') || '';
                const resp = await fetch('/api/quick_action?action=sprint_audit', {
                    headers: { 'X-Jira-PAT': pat },
                    signal: this.abortController.signal
                });
                if (!resp.ok) throw new Error("Quick Action API Failed: " + resp.statusText);
                const data = await resp.json();
                
                let html = '<agent-html><div class="bg-slate-800 border border-amber-500/30 rounded-lg p-4 mb-4"><h3 class="text-amber-400 font-bold mb-2">??? Governance Audit Findings</h3><table class="w-full text-sm text-left text-slate-300"><thead class="text-xs text-slate-400 bg-slate-900 uppercase"><tr><th>Key</th><th>Summary</th><th>Missing Element</th></tr></thead><tbody>';
                let found = false;
                if (data.audit_results && data.audit_results.missing_assignees) {
                    data.audit_results.missing_assignees.forEach(t => {
                        html += `<tr class="bg-slate-800 border-b border-slate-700"><td class="px-3 py-2 font-mono text-blue-400">${t.key}</td><td class="px-3 py-2">${t.summary}</td><td class="px-3 py-2 text-red-400">No Assignee</td></tr>`;
                        found = true;
                    });
                }
                html += '</tbody></table></div></agent-html>';
                
                if (!found) {
                    llmResp = { message: "Great news! All tickets in the current sprint have assignees." };
                } else {
                    llmResp = { message: "Here is the sprint audit report you requested:\n\n" + html };
                }
            } else {
                const historyToSend = this.messageHistory.slice(0, -1);
                llmResp = await API.llmChat(text, llmUrl, llmKey, llmModel, historyToSend, this.abortController.signal);
            }
            
            this.removeLoading(loadingId);
            let rawText = (typeof llmResp === 'string' ? llmResp : llmResp.message) || "";
            
            // Add agent response to history
            this.messageHistory.push({ role: 'assistant', content: rawText });
            
            // Generative UI Interception - JSON Cards
            const searchMatch = rawText.match(/<jira-search-results>([\s\S]*?)<\/jira-search-results>/i);
            const reportMatch = rawText.match(/<jira-sprint-report>([\s\S]*?)<\/jira-sprint-report>/i);
            const burndownMatch = rawText.match(/<jira-burndown>([\s\S]*?)<\/jira-burndown>/i);
            const auditMatch = rawText.match(/<jira-audit>([\s\S]*?)<\/jira-audit>/i);
            
            // Generative UI Interception - Raw HTML
            const htmlMatch = rawText.match(/<agent-html>([\s\S]*?)<\/agent-html>/i);
            
            if (searchMatch) {
                try {
                    const issuesJson = JSON.parse(searchMatch[1].trim());
                    rawText = rawText.replace(searchMatch[0], '').trim();
                    if (rawText) this.addMessage(rawText, 'agent');
                    this.addAgentCard({ issues: issuesJson }, 'search_results');
                } catch(e) {
                    console.error("Failed to parse GenUI JSON:", e);
                    this.addMessage(rawText, 'agent'); // fallback
                }
            } else if (reportMatch) {
                try {
                    const data = JSON.parse(reportMatch[1].trim());
                    rawText = rawText.replace(reportMatch[0], '').trim();
                    if (rawText) this.addMessage(rawText, 'agent');
                    this.addAgentCard(data, 'sprint_report');
                } catch(e) { console.error("Failed to parse GenUI JSON:", e); this.addMessage(rawText, 'agent'); }
            } else if (burndownMatch) {
                try {
                    const data = JSON.parse(burndownMatch[1].trim());
                    rawText = rawText.replace(burndownMatch[0], '').trim();
                    if (rawText) this.addMessage(rawText, 'agent');
                    this.addAgentCard(data, 'burndown');
                } catch(e) { console.error("Failed to parse GenUI JSON:", e); this.addMessage(rawText, 'agent'); }
            } else if (auditMatch) {
                try {
                    const data = JSON.parse(auditMatch[1].trim());
                    rawText = rawText.replace(auditMatch[0], '').trim();
                    if (rawText) this.addMessage(rawText, 'agent');
                    this.addAgentCard(data, 'audit');
                } catch(e) { console.error("Failed to parse GenUI JSON:", e); this.addMessage(rawText, 'agent'); }
            } else if (htmlMatch) {
                let htmlContent = htmlMatch[1].trim();
                // Convert Jira keys to clickable links inside custom HTML tables
                htmlContent = htmlContent.replace(/SIGPOSDEV-\d+/g, match => `<a href="http://jira.lge.com/issue/browse/${match}" target="_blank" class="text-blue-400 hover:underline">${match}</a>`);
                rawText = rawText.replace(htmlMatch[0], '').trim();
                if (rawText) this.addMessage(rawText, 'agent');
                
                // Render the raw HTML safely
                const div = document.createElement('div');
                div.className = 'flex gap-4 max-w-4xl w-full my-2';
                div.innerHTML = `
                  <div class="w-8 h-8 rounded-full bg-blue-500/20 border border-blue-500/50 flex items-center justify-center shrink-0 mt-1">
                    <i data-lucide="bot" class="w-4 h-4 text-blue-400"></i>
                  </div>
                  <div class="flex-1 overflow-x-auto">
                    ${htmlContent}
                  </div>
                `;
                this.messagesContainer.appendChild(div);
                if (typeof lucide !== 'undefined') lucide.createIcons();
                this.scrollToBottom();
                this.saveHistory();
                
            } else {
                this.addMessage(rawText, 'agent');
            }
        } else {
            this.removeLoading(loadingId);
            this.addMessage(`?? **Configuration Needed**: Please configure your Exacode LLM API Key in Settings to chat with the agent!`, 'agent', true);
        }

      } catch (error) {
        if (error.name === 'AbortError' || (error.message && error.message.includes('abort'))) {
            this.removeLoading(loadingId);
            this.addMessage(`?? **Request Cancelled**`, 'agent', true);
            return;
        }
        this.removeLoading(loadingId);
        console.error("Agent error:", error);
        let msg = "Failed to communicate with Jira.";
        if (error.message) {
            msg = error.message;
        } else if (typeof error === 'object') {
            try { msg = JSON.stringify(error); } catch(e) {}
        }
        this.addMessage(`?? **Agent Error**: ${msg}\n\n*Please make sure your Jira PAT is entered in ?? Settings and that the Jira server is reachable.*`, 'agent', true);
      } finally {
        this.abortController = null;
        const submitBtn = document.getElementById('chat-submit-btn');
        if (submitBtn) {
            submitBtn.classList.replace('bg-red-600', 'bg-blue-600');
            submitBtn.classList.replace('hover:bg-red-500', 'hover:bg-blue-500');
            submitBtn.innerHTML = '<i data-lucide="send" class="w-4 h-4"></i>';
            if (typeof lucide !== 'undefined') lucide.createIcons();
        }
      }
  },

  parseIntent(text) {
    const t = text.toLowerCase();
    if (t.includes('burndown') || t.includes('burn down') || t.includes('velocity')) return 'burndown';
    if (t.includes('report') || t.includes('health') || t.includes('sprint status') || t.includes('overview')) return 'sprint_report';
    if (t.includes('audit') || t.includes('label') || t.includes('governance') || t.includes('compliance')) return 'audit';
    if (t.includes('epic') || t.includes('initiative')) return 'epic';
    if (t.startsWith('find') || t.startsWith('search') || t.includes('ticket') || t.includes('bug') || t.includes('issue') || t.startsWith('project ')) return 'search';
    return null;
  },

  addMessage(text, sender, isError = false) {
    const div = document.createElement('div');
    div.className = `flex gap-4 max-w-3xl ${sender === 'user' ? 'ml-auto flex-row-reverse group' : ''}`;
    
    let avatar = '';
    let bubbleClass = '';
    let editButton = '';
    
    if (sender === 'user') {
      avatar = `
        <div class="w-8 h-8 rounded-full bg-slate-700 border border-slate-600 flex items-center justify-center shrink-0 mt-1">
          <i data-lucide="user" class="w-4 h-4 text-slate-300"></i>
        </div>
      `;
      bubbleClass = 'bg-blue-600 text-white rounded-tr-sm';
      editButton = `
        <button class="opacity-0 group-hover:opacity-100 transition-opacity text-slate-400 hover:text-white p-1 self-center" title="Edit this prompt" onclick="
          const input = document.getElementById('chat-input');
          if(input) { input.value = decodeURIComponent('${encodeURIComponent(text)}'); input.focus(); }
        ">
          <i data-lucide="edit-3" class="w-4 h-4"></i>
        </button>
      `;
    } else {
      avatar = `
        <div class="w-8 h-8 rounded-full bg-blue-500/20 border border-blue-500/50 flex items-center justify-center shrink-0 mt-1">
          <i data-lucide="bot" class="w-4 h-4 text-blue-400"></i>
        </div>
      `;
      bubbleClass = isError 
        ? 'bg-red-500/10 border border-red-500/30 text-red-300 rounded-tl-sm' 
        : 'bg-slate-700 border border-slate-600 text-slate-200 rounded-tl-sm shadow-sm prose prose-invert prose-blue max-w-none text-sm';
    }

    // Basic markdown conversion for bold and line breaks
    let formattedText = text;
    if (sender !== 'user' && typeof marked !== 'undefined') {
      marked.setOptions({ gfm: true, breaks: true });
      formattedText = marked.parse(text);
      // Convert Jira keys to clickable links if they are not already in a link
      formattedText = formattedText.replace(/SIGPOSDEV-\d+/g, match => `<a href="http://jira.lge.com/issue/browse/${match}" target="_blank" class="text-blue-400 hover:underline">${match}</a>`);
      // marked doesn't always preserve plain-text table spacing if the LLM forgot to use pipes,
      // so if there's no HTML table generated, we could inject white-space pre-wrap, 
      // but let's just let marked handle it.
    } else {
      formattedText = text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/  +/g, match => '&nbsp;'.repeat(match.length)) // Preserve spacing for LLM plain-text tables
        .replace(/\n/g, '<br>');
    }

    div.innerHTML = `
      ${avatar}
      <div class="space-y-1 w-full ${sender === 'user' ? 'items-end flex flex-col' : ''}">
        <div class="flex items-center gap-2 ${sender === 'user' ? 'flex-row-reverse' : ''} w-full max-w-full">
          <div class="p-4 rounded-2xl text-sm leading-relaxed ${bubbleClass} agent-content overflow-x-auto">
            ${formattedText}
          </div>
          ${editButton}
        </div>
        <div class="text-xs text-slate-500 ${sender === 'user' ? 'mr-1' : 'ml-1'}">${sender === 'user' ? 'You' : 'GPOS Jira Agent'} &bull; Just now</div>
      </div>
    `;

    this.messagesContainer.appendChild(div);
    if (typeof lucide !== 'undefined') lucide.createIcons();
    
    // Render mermaid diagrams if any exist
    if (sender !== 'user' && typeof mermaid !== 'undefined') {
      try {
        const mermaidBlocks = div.querySelectorAll('code.language-mermaid, code.language-xychart-beta');
        mermaidBlocks.forEach((block, idx) => {
          const container = document.createElement('div');
          container.className = 'mermaid my-4 bg-slate-800 rounded-lg p-4 flex justify-center overflow-x-auto';
          
          let content = block.textContent;
          
          // Fix xychart-beta null issue (Mermaid crashes if arrays have 'null')
          if (content.includes('xychart-beta')) {
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].trim().startsWith('line [') && lines[i].includes('null')) {
                 let arrStr = lines[i].substring(lines[i].indexOf('[') + 1, lines[i].indexOf(']'));
                 let parts = arrStr.split(',').map(p => p.trim());
                 let lastValid = '0';
                 for (let j = 0; j < parts.length; j++) {
                   if (parts[j] === 'null' || parts[j] === '') {
                      parts[j] = lastValid;
                   } else {
                      lastValid = parts[j];
                   }
                 }
                 lines[i] = lines[i].substring(0, lines[i].indexOf('[')) + '[' + parts.join(', ') + ']';
              }
            }
            content = lines.join('\n');
          }
          
          container.textContent = content;
          
          const pre = block.parentElement;
          pre.parentNode.replaceChild(container, pre);
        });
        
        mermaid.run({
          nodes: div.querySelectorAll('.mermaid')
        });
      } catch (e) {
        console.error("Mermaid error:", e);
      }
    }
    
    this.scrollToBottom();
    this.saveHistory();
  },

  addAgentCard(data, type) {
    const div = document.createElement('div');
    div.className = 'flex gap-4 max-w-4xl w-full';
    
    let content = '';

    // ==========================================
    // 1. SPRINT HEALTH REPORT CARD
    // ==========================================
    if (type === 'sprint_report') {
      const overview = data.overview || {};
      const compPct = Math.round(overview.completion_pct_points ?? data.completion_percentage ?? 0);
      const totalPts = Math.round(overview.total_points ?? data.total_points ?? 0);
      const donePts = Math.round(overview.done?.points ?? data.completed_points ?? 0);
      const totalTickets = overview.total_tickets ?? data.total_issues ?? 0;
      const doneTickets = overview.done?.tickets ?? 0;
      
      const atRisk = data.at_risk || {};
      const unassigned = atRisk.unassigned || [];
      const zeroPts = atRisk.zero_points || atRisk.zero_point || [];
      const blocked = atRisk.blocked || [];
      const totalRisk = unassigned.length + zeroPts.length + blocked.length;

      content = `
        <div class="bg-slate-800 border border-slate-700 rounded-2xl rounded-tl-sm shadow-lg overflow-hidden w-full">
          <div class="px-5 py-3 bg-slate-750 border-b border-slate-700 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="bar-chart-2" class="w-4 h-4 text-blue-400"></i>
              <span class="font-semibold text-slate-100 text-sm">Sprint Health Report: ${data.sprint_name || 'Active Sprint'}</span>
            </div>
            <span class="text-xs bg-blue-500/20 text-blue-300 px-2.5 py-0.5 rounded-full border border-blue-500/30 font-mono">${data.project_key || 'SIGPOSDEV'}</span>
          </div>
          <div class="p-5 space-y-4">
            <!-- 3 Stat Boxes -->
            <div class="grid grid-cols-3 gap-3">
              <div class="bg-slate-900/60 p-3 rounded-xl border border-slate-700/60 text-center">
                <div class="text-[11px] font-medium text-slate-400 mb-1">Completion</div>
                <div class="text-2xl font-bold text-emerald-400">${compPct}%</div>
                <div class="text-[10px] text-slate-500 mt-0.5">${donePts} / ${totalPts} pts</div>
              </div>
              <div class="bg-slate-900/60 p-3 rounded-xl border border-slate-700/60 text-center">
                <div class="text-[11px] font-medium text-slate-400 mb-1">Tickets</div>
                <div class="text-2xl font-bold text-blue-400">${totalTickets}</div>
                <div class="text-[10px] text-slate-500 mt-0.5">${doneTickets} done</div>
              </div>
              <div class="bg-slate-900/60 p-3 rounded-xl border border-slate-700/60 text-center">
                <div class="text-[11px] font-medium text-slate-400 mb-1">At Risk</div>
                <div class="text-2xl font-bold ${totalRisk > 0 ? 'text-amber-400' : 'text-slate-400'}">${totalRisk}</div>
                <div class="text-[10px] text-slate-500 mt-0.5">${unassigned.length} unassigned</div>
              </div>
            </div>

            <!-- Progress Bar -->
            <div>
              <div class="flex justify-between text-xs text-slate-400 mb-1.5">
                <span>Sprint Progress</span>
                <span class="font-semibold text-slate-200">${compPct}% by points</span>
              </div>
              <div class="h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-700/50 flex">
                <div class="bg-emerald-500 transition-all duration-700" style="width: ${compPct}%"></div>
              </div>
            </div>

            <!-- Summary Text -->
            <p class="text-xs text-slate-300 leading-relaxed bg-slate-900/40 p-3 rounded-lg border border-slate-700/40">
              ?? <strong>Sprint Status</strong>: Currently at <strong>${compPct}%</strong> completion (${donePts} of ${totalPts} points done across ${totalTickets} tickets). 
              ${totalRisk > 0 ? `?? There are <strong class="text-amber-400">${totalRisk} at-risk items</strong> (${unassigned.length} unassigned, ${zeroPts.length} zero-point).` : '? All tickets are properly assigned with story points.'}
            </p>
          </div>
        </div>
      `;

    // ==========================================
    // 2. BURNDOWN CHART CARD
    // ==========================================
    } else if (type === 'burndown') {
      const chartId = 'chat-burndown-' + Date.now();
      content = `
        <div class="bg-slate-800 border border-slate-700 rounded-2xl rounded-tl-sm shadow-lg overflow-hidden w-full">
          <div class="px-5 py-3 bg-slate-750 border-b border-slate-700 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="trending-down" class="w-4 h-4 text-emerald-400"></i>
              <span class="font-semibold text-slate-100 text-sm">Sprint Burndown: ${data.sprint_name || 'Active Sprint'}</span>
            </div>
            <span class="text-xs text-slate-400">Total: <strong class="text-white">${data.total_points || 0} pts</strong></span>
          </div>
          <div class="p-5">
            <div class="h-56 relative w-full mb-3">
              <canvas id="${chartId}"></canvas>
            </div>
            <div class="flex items-center justify-between text-xs text-slate-400 border-t border-slate-700/60 pt-3">
              <span class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"></span> Actual Remaining</span>
              <span class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span> Ideal Burn</span>
              <span class="text-slate-300">Remaining: <strong class="text-emerald-400">${Math.max(0, (data.total_points || 0) - (data.done_points || 0))} pts</strong></span>
            </div>
          </div>
        </div>
      `;

      // Render chart after DOM insertion
      setTimeout(() => {
        const ctx = document.getElementById(chartId);
        if (ctx) {
          new Chart(ctx, {
            type: 'line',
            data: {
              labels: data.days || data.labels || [],
              datasets: [
                {
                  label: 'Actual Remaining',
                  data: data.actual || [],
                  borderColor: '#22c55e',
                  backgroundColor: 'rgba(34, 197, 94, 0.08)',
                  fill: true,
                  tension: 0.3,
                  borderWidth: 2.5,
                  pointRadius: 4,
                  pointBackgroundColor: '#22c55e'
                },
                {
                  label: 'Ideal Burn',
                  data: data.ideal || [],
                  borderColor: '#3b82f6',
                  borderDash: [5, 5],
                  fill: false,
                  tension: 0,
                  borderWidth: 2,
                  pointRadius: 0
                }
              ]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { display: false }, datalabels: { display: false } },
              scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(51, 65, 85, 0.4)' }, ticks: { color: '#94a3b8' } },
                x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
              }
            }
          });
        }
      }, 50);

    // ==========================================
    // 3. AUDIT GOVERNANCE CARD
    // ==========================================
    } else if (type === 'audit') {
      const missingLabels = data?.missing_labels || [];
      const missingAssignees = data?.missing_assignees || [];
      const zeroPoints = data?.zero_points || [];
      const isClean = missingLabels.length === 0 && missingAssignees.length === 0 && zeroPoints.length === 0;

      let rows = '';
      missingLabels.slice(0, 5).forEach(item => {
        const k = item.key || item;
        const s = item.summary || '';
        rows += `
          <div class="flex items-center justify-between py-2 border-b border-slate-700/40 text-xs">
            <span class="font-mono text-blue-400 font-semibold">${k}</span>
            <span class="text-slate-300 truncate max-w-xs">${s}</span>
            <span class="bg-amber-500/10 text-amber-400 border border-amber-500/20 px-2 py-0.5 rounded text-[10px]">Missing AX Label</span>
          </div>
        `;
      });

      zeroPoints.slice(0, 5).forEach(item => {
        const k = item.key || item;
        const s = item.summary || '';
        rows += `
          <div class="flex items-center justify-between py-2 border-b border-slate-700/40 text-xs">
            <span class="font-mono text-blue-400 font-semibold">${k}</span>
            <span class="text-slate-300 truncate max-w-xs">${s}</span>
            <span class="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded text-[10px]">0 Story Points</span>
          </div>
        `;
      });

      content = `
        <div class="bg-slate-800 border border-slate-700 rounded-2xl rounded-tl-sm shadow-lg overflow-hidden w-full">
          <div class="px-5 py-3 bg-slate-750 border-b border-slate-700 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="shield-alert" class="w-4 h-4 ${isClean ? 'text-emerald-400' : 'text-amber-400'}"></i>
              <span class="font-semibold text-slate-100 text-sm">Sprint Governance Audit: ${data?.sprint_name || 'Active Sprint'}</span>
            </div>
            <span class="text-xs ${isClean ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'} px-2.5 py-0.5 rounded-full border">
              ${isClean ? 'COMPLIANT' : `${missingLabels.length + zeroPoints.length + missingAssignees.length} Flags`}
            </span>
          </div>
          <div class="p-5 space-y-3">
            <div class="grid grid-cols-3 gap-2 text-center text-xs">
              <div class="bg-slate-900/60 p-2.5 rounded-lg border border-slate-700/50">
                <div class="text-slate-400 text-[10px]">Missing AX Label</div>
                <div class="font-bold text-base ${missingLabels.length ? 'text-amber-400' : 'text-emerald-400'}">${missingLabels.length}</div>
              </div>
              <div class="bg-slate-900/60 p-2.5 rounded-lg border border-slate-700/50">
                <div class="text-slate-400 text-[10px]">Missing Assignee</div>
                <div class="font-bold text-base ${missingAssignees.length ? 'text-amber-400' : 'text-emerald-400'}">${missingAssignees.length}</div>
              </div>
              <div class="bg-slate-900/60 p-2.5 rounded-lg border border-slate-700/50">
                <div class="text-slate-400 text-[10px]">Zero Story Points</div>
                <div class="font-bold text-base ${zeroPoints.length ? 'text-red-400' : 'text-emerald-400'}">${zeroPoints.length}</div>
              </div>
            </div>
            ${rows ? `<div class="mt-2 divide-y divide-slate-700/30">${rows}</div>` : '<p class="text-xs text-emerald-400 py-2">?? All tickets pass process compliance!</p>'}
          </div>
        </div>
      `;

    // ==========================================
    // 4. SEARCH / ISSUE RESULTS CARD
    // ==========================================
    } else if (type === 'search_results' || type === 'epic_results') {
      const issues = data.issues || [];
      const count = data.total ?? issues.length;

      let itemsHtml = issues.slice(0, 10).map(issue => {
        let badgeClass = issue.status === 'Done' || issue.status === 'Closed' || issue.status === 'Resolved' ? 'badge-done' : (issue.status.includes('Progress') || issue.status.includes('Review') ? 'badge-in-progress' : 'badge-todo');
        return `
          <a href="${issue.link || `http://jira.lge.com/issue/browse/${issue.key}`}" target="_blank" class="flex items-center justify-between p-2.5 bg-slate-900/50 border border-slate-700/50 rounded-lg hover:border-blue-500/50 transition-colors group">
            <div class="flex items-center gap-3 overflow-hidden">
              <span class="text-xs font-mono font-bold text-blue-400 shrink-0">${issue.key}</span>
              <span class="text-xs text-slate-200 truncate group-hover:text-blue-300 transition-colors">${issue.summary}</span>
            </div>
            <div class="flex items-center gap-2 shrink-0 ml-2">
              <span class="text-[11px] text-slate-400 hidden sm:inline">${issue.assignee || 'Unassigned'}</span>
              <span class="badge ${badgeClass} text-[10px]">${issue.status}</span>
            </div>
          </a>
        `;
      }).join('');

      content = `
        <div class="bg-slate-800 border border-slate-700 rounded-2xl rounded-tl-sm shadow-lg overflow-hidden w-full">
          <div class="px-5 py-3 bg-slate-750 border-b border-slate-700 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="${type === 'epic_results' ? 'target' : 'search'}" class="w-4 h-4 text-blue-400"></i>
              <span class="font-semibold text-slate-100 text-sm">${type === 'epic_results' ? 'Active Epics & Initiatives' : 'Jira Search Results'}</span>
            </div>
            <span class="text-xs bg-slate-900 text-slate-300 px-2.5 py-0.5 rounded-full border border-slate-700">Found ${count} Issues</span>
          </div>
          <div class="p-4 space-y-2">
            ${itemsHtml || '<p class="text-xs text-slate-400 p-2">No matching issues found.</p>'}
          </div>
        </div>
      `;
    }

    div.innerHTML = `
      <div class="w-8 h-8 rounded-full bg-blue-500/20 border border-blue-500/50 flex items-center justify-center shrink-0 mt-1">
        <i data-lucide="bot" class="w-4 h-4 text-blue-400"></i>
      </div>
      <div class="space-y-1 flex-1">
        ${content}
        <div class="text-xs text-slate-500 ml-1">GPOS Jira Agent &bull; Just now</div>
      </div>
    `;

    this.messagesContainer.appendChild(div);
    if (typeof lucide !== 'undefined') lucide.createIcons();
    this.scrollToBottom();
    this.saveHistory();
  },

  showLoading() {
    const id = 'loading-' + Date.now();
    const div = document.createElement('div');
    div.id = id;
    div.className = 'flex gap-4 max-w-3xl';
    
    div.innerHTML = `
      <div class="w-8 h-8 rounded-full bg-blue-500/20 border border-blue-500/50 flex items-center justify-center shrink-0 mt-1">
        <i data-lucide="bot" class="w-4 h-4 text-blue-400"></i>
      </div>
      <div class="bg-slate-700 border border-slate-600 px-4 py-3 rounded-2xl rounded-tl-sm flex items-center gap-1.5 w-18 shadow-sm">
        <div class="w-2 h-2 bg-blue-400 rounded-full typing-dot"></div>
        <div class="w-2 h-2 bg-blue-400 rounded-full typing-dot"></div>
        <div class="w-2 h-2 bg-blue-400 rounded-full typing-dot"></div>
      </div>
    `;

    this.messagesContainer.appendChild(div);
    if (typeof lucide !== 'undefined') lucide.createIcons();
    this.scrollToBottom();
    return id;
  },

  removeLoading(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  },

  scrollToBottom() {
    this.messagesContainer.scrollTo({
      top: this.messagesContainer.scrollHeight,
      behavior: 'smooth'
    });
  }
};
