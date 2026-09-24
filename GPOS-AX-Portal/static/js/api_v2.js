const API = {
  baseUrl: '/api',
  
  getHeaders() {
    const pat = localStorage.getItem('jira_pat') || '';
    return { 
      'Content-Type': 'application/json', 
      'X-Jira-PAT': pat 
    };
  },

  async _fetch(endpoint, options = {}, abortSignal = null) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = this.getHeaders();
    
    try {
      const response = await fetch(url, { ...options, headers, signal: abortSignal });
      if (!response.ok) {
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
  
  async getSprintReport(projectKey = 'SIGPOSDEV') {
    return this._fetch(`/sprint/report?project_key=${projectKey}`);
  },
  
  async getSprintBurndown(projectKey = 'SIGPOSDEV') {
    return this._fetch(`/sprint/burndown?project_key=${projectKey}`);
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
  
  async llmChat(message, llmUrl, llmKey, llmModel, history = [], abortSignal = null) {
    // Backward compatibility if chat.js is cached and only passes 4 arguments
    if (Array.isArray(llmModel)) {
      abortSignal = history;
      history = llmModel;
      llmModel = 'Chat-EXACODE-A';
    }
    return this._fetch('/chat', {
      method: 'POST',
      body: JSON.stringify({ message: message, llm_url: llmUrl, llm_key: llmKey, llm_model: llmModel, history: history })
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
  }
};
