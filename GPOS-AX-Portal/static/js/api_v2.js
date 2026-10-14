const API = {
  baseUrl: '/api',
  
  // Dynamic project key: reads from localStorage, defaults to SIGPOSDEV
  getProjectKey() {
    return localStorage.getItem('jira_project_key') || 'SIGPOSDEV';
  },

  getHeaders() {
    const pat = localStorage.getItem('jira_pat') || '';
    const collabPat = localStorage.getItem('collab_pat') || '';
    const token = localStorage.getItem('auth_token') || '';
    const headers = { 
      'Content-Type': 'application/json', 
      'X-Jira-PAT': pat,
      'X-Collab-PAT': collabPat
    };
    if (token) {
      headers['Authorization'] = 'Bearer ' + token;
    }
    return headers;
  },

  async _fetch(endpoint, options = {}, abortSignal = null) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = this.getHeaders();
    
    try {
      const response = await fetch(url, { ...options, headers, signal: abortSignal });
      if (!response.ok) {
        if (response.status === 401) {
          console.warn('Token expired or unauthorized. Redirecting to login...');
          this.logout();
          return;
        }
        let errMsg = `API Error (${response.status}): ${response.statusText}`;
        try {
          const errJson = await response.json();
          if (errJson.detail) {
              errMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
          }
        } catch (e) {}
        throw new Error(errMsg);
      }
      return await response.json();
    } catch (error) {
      console.error(`Error fetching ${url}:`, error);
      throw error;
    }
  },
  
  async getSprintReport(projectKey) {
    const pk = projectKey || this.getProjectKey();
    return this._fetch(`/sprint/report?project_key=${pk}`);
  },
  
  async getSprintBurndown(projectKey) {
    const pk = projectKey || this.getProjectKey();
    return this._fetch(`/sprint/burndown?project_key=${pk}`);
  },
  
  async getMentions() {
    return this._fetch('/mentions');
  },
  
  async searchIssues(jql, maxResults = 50) {
    return this._fetch(`/search?jql=${encodeURIComponent(jql)}&max_results=${maxResults}`);
  },
  
  async getAgents() {
    return this._fetch('/agents');
  },
  
  async getUserProfile() {
    return this._fetch('/user');
  },
  
  async llmChat(message, llmUrl, llmKey, llmModel, history = [], abortSignal = null, images = [], agentId = 'jira-agent') {
    // Backward compatibility if chat.js is cached and only passes 4 arguments
    if (Array.isArray(llmModel)) {
      abortSignal = history;
      history = llmModel;
      llmModel = 'Chat-EXACODE-A';
    }
    const projectKey = this.getProjectKey();
    const collabPat = localStorage.getItem('collab_pat') || '';
    return this._fetch('/chat', {
      method: 'POST',
      body: JSON.stringify({ message: message, images: images, llm_url: llmUrl, llm_key: llmKey, llm_model: llmModel, project_key: projectKey, history: history, agent_id: agentId, collab_pat: collabPat })
    }, abortSignal);
  },
  
  async getIssue(issueKey) {
    return this._fetch(`/issue/${issueKey}`);
  },
  
  async executeAction(action, params = {}) {
    return this._fetch('/agent/action', {
      method: 'POST',
      body: JSON.stringify({ action, ...params })
    });
  },

  async login(username, password) {
    const response = await fetch(this.baseUrl + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    });
    if (!response.ok) {
      let errMsg = 'Login failed';
      try {
        const errJson = await response.json();
        if (errJson.detail) errMsg = errJson.detail;
      } catch(e) {}
      throw new Error(errMsg);
    }
    return await response.json();
  },

  async verifyAuth() {
    const token = localStorage.getItem('auth_token');
    if (!token) return false;
    try {
      const response = await fetch(this.baseUrl + '/auth/verify', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      return response.ok;
    } catch(e) {
      return false;
    }
  },

  logout() {
    const wasLoggedIn = !!localStorage.getItem('auth_token');
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_username');
    localStorage.removeItem('auth_role');
    if (wasLoggedIn) {
        window.location.reload();
    }
  },

  async recordTelemetry(agentId, sessionId, durationSeconds) {
    try {
      await this._fetch('/telemetry', {
        method: 'POST',
        body: JSON.stringify({ agent_id: agentId, session_id: sessionId, duration_seconds: durationSeconds })
      });
    } catch(e) {
      // Silent fail - telemetry is non-critical
    }
  },

  async getAdminStats() {
    return this._fetch('/admin/stats');
  },

    async getAdminUserStats(username) {
    const response = await fetch(this.baseUrl + '/admin/user/' + encodeURIComponent(username) + '/stats', {
      headers: this.getHeaders()
    });
    if (!response.ok) throw new Error('Failed to fetch user stats');
    return await response.json();
  },
  async toggleUserAccess(username, allowed) {
    return this._fetch('/admin/toggle-user', {
      method: 'POST',
      body: JSON.stringify({ username: username, allowed: allowed })
    });
  }
};
