/**
 * profiles_v2.js - Multi-Profile Manager for Credential & LLM Settings
 * Modeled after WinSCP / FileZilla Site Manager.
 * Supports multiple named profiles, default profile selection, instant switching, and presets.
 */

(function () {
  'use strict';

  const KEY_PROFILES = 'credential_profiles';
  const KEY_ACTIVE_ID = 'active_credential_profile_id';
  const KEY_OWNER = 'credential_profiles_owner';
  const KEY_UPDATED_AT = 'credential_profiles_updated_at';
  const KEY_DIRTY = 'credential_profiles_dirty';
  const LEGACY_KEYS = ['jira_pat', 'llm_api_url', 'llm_api_key', 'llm_api_model', 'collab_pat'];

  const ProfilesManager = {
    selectedModalProfileId: null,
    profileTab: 'mine',
    _catalogRows: [],
    _catalogMessage: '',
    _deleteSelection: {},
    _catalogDeleteSelection: {},
    _pushChain: Promise.resolve(),

    init() {
      this.setupGlobalListeners();
      if (!localStorage.getItem('auth_token')) {
        this.migrateLegacyIfNeeded();
        this.finishLocalInit();
      }
    },

    finishLocalInit() {
      const active = this.getActive();
      if (active) {
        this.syncToLegacyKeys(active);
      }
      this.updateHeaderProfileBadge();
    },

    hasLegacySecrets() {
      return LEGACY_KEYS.some(function (key) {
        const value = localStorage.getItem(key);
        return value !== null && value !== '';
      });
    },

    hasMeaningfulLocalProfiles() {
      if (this.hasLegacySecrets()) return true;
      const raw = localStorage.getItem(KEY_PROFILES);
      if (!raw) return false;
      try {
        const profiles = JSON.parse(raw);
        if (!Array.isArray(profiles) || profiles.length === 0) return false;
        if (profiles.length > 1) return true;
        const profile = profiles[0] || {};
        if ((profile.name || '') !== 'Default Profile') return true;
        return ['jiraPat', 'llmUrl', 'llmKey', 'llmModel', 'collabPat'].some(function (field) {
          return !!profile[field];
        });
      } catch (e) {
        return false;
      }
    },

    clearLegacyKeys() {
      LEGACY_KEYS.forEach(function (key) {
        localStorage.removeItem(key);
      });
    },

    clearCredentialCache() {
      localStorage.removeItem(KEY_PROFILES);
      localStorage.removeItem(KEY_ACTIVE_ID);
      localStorage.removeItem(KEY_OWNER);
      localStorage.removeItem(KEY_UPDATED_AT);
      localStorage.removeItem(KEY_DIRTY);
      this.clearLegacyKeys();
    },

    applyServerDocument(doc) {
      const profiles = doc && Array.isArray(doc.profiles) ? doc.profiles : [];
      this.writeLocal(profiles);
      if (doc && doc.activeId && profiles.some(function (p) { return p.id === doc.activeId; })) {
        localStorage.setItem(KEY_ACTIVE_ID, doc.activeId);
      } else if (profiles.length) {
        const fallback = profiles.find(function (p) { return p.isDefault; }) || profiles[0];
        localStorage.setItem(KEY_ACTIVE_ID, fallback.id);
      } else {
        localStorage.removeItem(KEY_ACTIVE_ID);
      }
      if (doc && doc.updatedAt) {
        localStorage.setItem(KEY_UPDATED_AT, doc.updatedAt);
      } else {
        localStorage.removeItem(KEY_UPDATED_AT);
      }
      const username = localStorage.getItem('auth_username') || '';
      if (username) localStorage.setItem(KEY_OWNER, username);
      localStorage.removeItem(KEY_DIRTY);
      const active = this.getActive();
      if (active) this.syncToLegacyKeys(active);
      else this.clearLegacyKeys();
      this.updateHeaderProfileBadge();
      const modal = document.getElementById('settings-modal');
      if (modal && !modal.classList.contains('hidden')) {
        this.selectedModalProfileId = this.getActiveId();
        this.renderModal();
      }
    },

    async hydrateFromServer() {
      if (!localStorage.getItem('auth_token')) {
        this.migrateLegacyIfNeeded();
        this.finishLocalInit();
        return;
      }

      const username = localStorage.getItem('auth_username') || '';
      const owner = localStorage.getItem(KEY_OWNER) || '';
      const ownerIsOther = !!(owner && username && owner !== username);
      let shouldUpload = this.hasMeaningfulLocalProfiles();
      const dirty = localStorage.getItem(KEY_DIRTY) === '1' && shouldUpload && !ownerIsOther;

      if (ownerIsOther) {
        this.clearCredentialCache();
        shouldUpload = false;
      }

      if (dirty) {
        this.migrateLegacyIfNeeded();
        this.finishLocalInit();
        await this.pushToServer();
        return;
      }

      let remote;
      try {
        remote = await API.getCredentialProfiles();
      } catch (e) {
        this.migrateLegacyIfNeeded();
        this.finishLocalInit();
        this.showToast('Could not load profiles from the server. Using this browser\'s saved profiles.');
        return;
      }

      if (remote && remote.updatedAt) {
        this.applyServerDocument(remote);
        return;
      }

      if (shouldUpload) {
        this.migrateLegacyIfNeeded();
        this.finishLocalInit();
        await this.pushToServer();
        return;
      }

      this.migrateLegacyIfNeeded();
      this.finishLocalInit();
    },

    pushToServer() {
      if (!localStorage.getItem('auth_token')) return Promise.resolve(false);
      const run = () => this._pushToServerNow();
      this._pushChain = (this._pushChain || Promise.resolve()).then(run, run);
      return this._pushChain;
    },

    async _pushToServerNow() {
      if (!localStorage.getItem('auth_token')) return false;
      if (typeof API === 'undefined' || !API.putCredentialProfiles) return false;
      const base = localStorage.getItem(KEY_UPDATED_AT) || null;
      try {
        const result = await API.putCredentialProfiles({
          profiles: this.getAll(),
          activeId: this.getActiveId(),
          baseUpdatedAt: base
        });
        if (!result || result.unauthorized) return false;
        if (result.conflict) {
          this.applyServerDocument(result);
          this.showToast('Profiles were updated in another session. Loaded the latest copy.');
          return true;
        }
        if (result.updatedAt) localStorage.setItem(KEY_UPDATED_AT, result.updatedAt);
        const username = localStorage.getItem('auth_username') || '';
        if (username) localStorage.setItem(KEY_OWNER, username);
        localStorage.removeItem(KEY_DIRTY);
        return true;
      } catch (e) {
        localStorage.setItem(KEY_DIRTY, '1');
        this.showToast('Could not save profiles to the server. They are kept in this browser.');
        return false;
      }
    },

    migrateLegacyIfNeeded() {
      let profiles = this.getAll();
      if (!profiles || profiles.length === 0) {
        const legacyPat = localStorage.getItem('jira_pat') || '';
        const legacyLlmUrl = localStorage.getItem('llm_api_url') || '';
        const legacyLlmKey = localStorage.getItem('llm_api_key') || '';
        const legacyLlmModel = localStorage.getItem('llm_api_model') || '';
        const legacyCollabPat = localStorage.getItem('collab_pat') || '';

        const defaultProfile = {
          id: 'prof_' + Date.now(),
          name: 'Default Profile',
          isDefault: true,
          jiraPat: legacyPat,
          llmUrl: legacyLlmUrl,
          llmKey: legacyLlmKey,
          llmModel: legacyLlmModel,
          collabPat: legacyCollabPat,
          createdAt: Date.now(),
          updatedAt: Date.now()
        };

        profiles = [defaultProfile];
        this.writeLocal(profiles);
        localStorage.setItem(KEY_ACTIVE_ID, defaultProfile.id);
      } else {
        // Ensure at least one profile is default and active ID is valid
        let defaultExists = profiles.some(p => p.isDefault);
        if (!defaultExists && profiles.length > 0) {
          profiles[0].isDefault = true;
          this.writeLocal(profiles);
        }
        let activeId = localStorage.getItem(KEY_ACTIVE_ID);
        if (!activeId || !profiles.some(p => p.id === activeId)) {
          const defaultProf = profiles.find(p => p.isDefault) || profiles[0];
          localStorage.setItem(KEY_ACTIVE_ID, defaultProf.id);
        }
      }
    },

    getAll() {
      try {
        return JSON.parse(localStorage.getItem(KEY_PROFILES) || '[]');
      } catch (e) {
        console.error('Failed to parse profiles from localStorage', e);
        return [];
      }
    },

    writeLocal(profiles) {
      try {
        localStorage.setItem(KEY_PROFILES, JSON.stringify(profiles));
      } catch (e) {
        console.error('Failed to write profiles to localStorage', e);
      }
    },

    saveAll(profiles) {
      this.writeLocal(profiles);
      if (localStorage.getItem('auth_token')) {
        localStorage.setItem(KEY_DIRTY, '1');
        return this.pushToServer();
      }
      return Promise.resolve(false);
    },

    get(id) {
      const profiles = this.getAll();
      return profiles.find(p => p.id === id) || null;
    },

    getActiveId() {
      return localStorage.getItem(KEY_ACTIVE_ID);
    },

    getActive() {
      const activeId = this.getActiveId();
      const profiles = this.getAll();
      return profiles.find(p => p.id === activeId) || profiles.find(p => p.isDefault) || profiles[0] || null;
    },

    syncToLegacyKeys(profile) {
      if (!profile) return;
      try {
        if (profile.jiraPat && profile.jiraPat.trim()) {
          localStorage.setItem('jira_pat', profile.jiraPat.trim());
        } else {
          const globalPat = localStorage.getItem('jira_pat');
          if (globalPat) profile.jiraPat = globalPat;
        }
        if (profile.collabPat && profile.collabPat.trim()) {
          localStorage.setItem('collab_pat', profile.collabPat.trim());
        } else {
          const globalCollab = localStorage.getItem('collab_pat');
          if (globalCollab) profile.collabPat = globalCollab;
        }
        if (profile.llmUrl !== undefined) localStorage.setItem('llm_api_url', profile.llmUrl);
        if (profile.llmKey !== undefined) localStorage.setItem('llm_api_key', profile.llmKey);
        if (profile.llmModel !== undefined) localStorage.setItem('llm_api_model', profile.llmModel);
      } catch (e) {
        console.error('Failed to sync profile to legacy keys', e);
      }
    },

    create(baseData = {}) {
      const profiles = this.getAll();
      const newId = 'prof_' + Date.now();
      const newProfile = {
        id: newId,
        name: baseData.name || `Profile ${profiles.length + 1}`,
        isDefault: profiles.length === 0,
        jiraPat: baseData.jiraPat || '',
        llmUrl: baseData.llmUrl || '',
        llmKey: baseData.llmKey || '',
        llmModel: baseData.llmModel || '',
        collabPat: baseData.collabPat || '',
        createdAt: Date.now(),
        updatedAt: Date.now()
      };

      profiles.push(newProfile);
      this.saveAll(profiles);
      this.selectedModalProfileId = newId;
      this.renderModal();
      this.showToast(`Created new profile: "${newProfile.name}"`);
      return newProfile;
    },

    duplicate(id) {
      const source = this.get(id);
      if (!source) return;
      const clone = {
        ...source,
        name: `${source.name} (Copy)`
      };
      delete clone.id;
      delete clone.isDefault;
      delete clone.createdAt;
      delete clone.updatedAt;
      return this.create(clone);
    },

    save(profileData) {
      if (!profileData || !profileData.id) return;
      let profiles = this.getAll();
      const idx = profiles.findIndex(p => p.id === profileData.id);
      if (idx === -1) return;

      if (profileData.isDefault) {
        profiles.forEach(p => p.isDefault = false);
      }

      profiles[idx] = {
        ...profiles[idx],
        ...profileData,
        name: (profileData.name || '').trim() || 'Untitled Profile',
        updatedAt: Date.now()
      };

      this.saveAll(profiles);

      // If active profile was updated, sync active keys
      if (this.getActiveId() === profileData.id) {
        this.syncToLegacyKeys(profiles[idx]);
        this.updateHeaderProfileBadge();
      }

      this.renderModal();
      this.showToast(`Saved profile: "${profiles[idx].name}"`);
    },

    setDefault(id) {
      let profiles = this.getAll();
      const target = profiles.find(p => p.id === id);
      if (!target) return;
      if (target.isDefault) {
        this.updateDefaultButton(true);
        this.showToast('"' + target.name + '" already opens with the portal.');
        return;
      }

      profiles.forEach(p => p.isDefault = (p.id === id));
      this.saveAll(profiles);
      this.renderModal();
      this.showToast('"' + target.name + '" will open with the portal.');
    },

    updateDefaultButton(isDefault) {
      const btn = document.getElementById('profile-set-default-btn');
      if (!btn) return;
      const on = !!isDefault;
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.disabled = on;
      btn.className = on
        ? 'px-2.5 py-1 bg-amber-500 text-slate-950 border border-amber-300 rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors cursor-default'
        : 'px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 border border-slate-600 rounded-lg text-xs font-medium flex items-center gap-1 transition-colors';
      btn.innerHTML = '<i data-lucide="star" class="w-3 h-3"></i><span id="profile-set-default-label">' + (on ? 'Default selected' : 'Set as Default') + '</span>';
      this.safeCreateIcons();
    },

    activate(id, reloadPage = false) {
      const menu = document.getElementById('header-profile-menu');
      if (menu) menu.classList.add('hidden');

      const profile = this.get(id);
      if (!profile) return;

      localStorage.setItem(KEY_ACTIVE_ID, id);
      this.syncToLegacyKeys(profile);
      if (localStorage.getItem('auth_token')) {
        localStorage.setItem(KEY_DIRTY, '1');
        this.pushToServer();
      }
      this.updateHeaderProfileBadge();
      this.renderModal();
      this.showToast(`Activated profile: "${profile.name}"`);

      if (reloadPage) {
        setTimeout(() => window.location.reload(), 300);
      }
    },

    toggleDeleteSelection(id, checked) {
      if (!id) return;
      if (checked) this._deleteSelection[id] = true;
      else delete this._deleteSelection[id];
      this.updateBulkDeleteBar();
    },

    clearDeleteSelection() {
      this._deleteSelection = {};
      this.updateBulkDeleteBar();
      this.renderModal();
    },

    updateBulkDeleteBar() {
      const bar = document.getElementById('profiles-bulk-delete-bar');
      const countEl = document.getElementById('profiles-bulk-delete-count');
      const ids = Object.keys(this._deleteSelection || {});
      if (bar) bar.classList.toggle('hidden', ids.length === 0);
      if (countEl) countEl.textContent = ids.length === 1 ? '1 selected' : (ids.length + ' selected');
      const teamBtn = document.getElementById('team-delete-selected-btn');
      const catalogIds = Object.keys(this._catalogDeleteSelection || {});
      if (teamBtn) teamBtn.classList.toggle('hidden', catalogIds.length === 0);
    },

    deleteSelectedProfiles() {
      const ids = Object.keys(this._deleteSelection || {});
      if (!ids.length) return;
      this.delete(ids);
    },

    toggleCatalogDeleteSelection(profileId, checked) {
      if (!profileId) return;
      if (checked) this._catalogDeleteSelection[profileId] = true;
      else delete this._catalogDeleteSelection[profileId];
      this.updateBulkDeleteBar();
    },

    deleteSelectedOwnCatalogProfiles() {
      const ids = Object.keys(this._catalogDeleteSelection || {});
      if (!ids.length) return;
      this.delete(ids).then(() => {
        this._catalogDeleteSelection = {};
        this.updateBulkDeleteBar();
        this.loadSharedCatalog();
      });
    },

    async delete(idOrIds) {
      const ids = Array.isArray(idOrIds) ? idOrIds.filter(Boolean) : [idOrIds].filter(Boolean);
      if (!ids.length) return false;

      let profiles = this.getAll();
      const targets = profiles.filter((profile) => ids.indexOf(profile.id) !== -1);
      if (!targets.length) return false;

      const label = targets.length === 1
        ? '"' + targets[0].name + '"'
        : targets.length + ' profiles';
      if (!window.confirm('Delete ' + label + '? This updates the shared database for every site that uses it.')) {
        return false;
      }

      const remove = {};
      ids.forEach((id) => { remove[id] = true; });
      const removedDefault = targets.some((profile) => profile.isDefault);
      const wasActive = !!remove[this.getActiveId()];
      profiles = profiles.filter((profile) => !remove[profile.id]);

      if (profiles.length && removedDefault) {
        profiles[0].isDefault = true;
      }
      if (profiles.length && wasActive) {
        const nextActive = profiles.find((profile) => profile.isDefault) || profiles[0];
        localStorage.setItem(KEY_ACTIVE_ID, nextActive.id);
        this.syncToLegacyKeys(nextActive);
      }

      ids.forEach((id) => {
        delete this._deleteSelection[id];
        delete this._catalogDeleteSelection[id];
      });

      if (!profiles.length) {
        if (localStorage.getItem('auth_token') && typeof API !== 'undefined' && API.deleteCredentialProfiles) {
          try {
            const result = await API.deleteCredentialProfiles();
            if (result && !result.unauthorized) this.applyServerDocument(result);
            else this.applyServerDocument({ profiles: [], activeId: null, updatedAt: null });
          } catch (e) {
            this.showToast(e.message || 'Could not delete profiles from the shared database.');
            return false;
          }
        } else {
          this.applyServerDocument({ profiles: [], activeId: null, updatedAt: null });
        }
        this.selectedModalProfileId = null;
        this.updateBulkDeleteBar();
        this.renderModal();
        this.loadSharedCatalog();
        this.showToast(targets.length === 1 ? 'Deleted that profile.' : 'Deleted the selected profiles.');
        return true;
      }

      await this.saveAll(profiles);
      this.selectedModalProfileId = profiles.some((profile) => profile.id === this.selectedModalProfileId)
        ? this.selectedModalProfileId
        : profiles[0].id;
      this.updateHeaderProfileBadge();
      this.updateBulkDeleteBar();
      this.renderModal();
      this.loadSharedCatalog();
      this.showToast(targets.length === 1 ? 'Deleted "' + targets[0].name + '".' : 'Deleted ' + targets.length + ' profiles.');
      return true;
    },

    updateHeaderProfileBadge() {
      const active = this.getActive();
      const el = document.getElementById('header-profile-name');
      if (el) {
        el.textContent = active ? active.name : 'Default Profile';
      }
      const modelBadge = document.getElementById('header-profile-model');
      if (modelBadge && active) {
        modelBadge.textContent = active.llmModel || 'No Model';
      }
    },

    toggleHeaderDropdown() {
      const menu = document.getElementById('header-profile-menu');
      if (!menu) return;
      const isHidden = menu.classList.contains('hidden');
      if (isHidden) {
        this.renderHeaderDropdown();
        menu.classList.remove('hidden');
      } else {
        menu.classList.add('hidden');
      }
    },

    safeCreateIcons() {
      try {
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
          window.lucide.createIcons();
        }
      } catch (e) {
        console.warn('Lucide icon warning:', e);
      }
    },

    renderHeaderDropdown() {
      const menu = document.getElementById('header-profile-menu');
      if (!menu) return;
      const profiles = this.getAll();
      const activeId = this.getActiveId();

      let html = `
        <div class="px-3 py-2 border-b border-slate-700/60 flex items-center justify-between">
          <span class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Credential Profiles</span>
          <button type="button" onclick="event.stopPropagation(); window.profiles.openSettingsModal();" class="text-[11px] text-blue-400 hover:text-blue-300 font-medium cursor-pointer">Manage</button>
        </div>
        <div class="py-1 max-h-60 overflow-y-auto">
      `;

      profiles.forEach(p => {
        const isActive = p.id === activeId;
        html += `
          <div onclick="event.stopPropagation(); window.profiles.activate('${p.id}');" class="px-3 py-2 hover:bg-slate-700/50 cursor-pointer flex items-center justify-between transition-colors ${isActive ? 'bg-blue-600/10 text-blue-400 font-medium' : 'text-slate-300'}">
            <div class="min-w-0 pr-2">
              <div class="flex items-center gap-1.5 truncate">
                ${p.isDefault ? '<span title="Default Profile" class="text-amber-400">★</span>' : ''}
                <span class="truncate text-xs">${this.escapeHtml(p.name)}</span>
              </div>
              <div class="text-[10px] text-slate-500 truncate">${this.escapeHtml(p.llmModel || 'No Model Set')}</div>
            </div>
            ${isActive ? '<span class="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)] shrink-0"></span>' : ''}
          </div>
        `;
      });

      html += `
        </div>
        <div class="p-2 border-t border-slate-700/60 bg-slate-800/40">
          <button type="button" onclick="event.stopPropagation(); window.profiles.openSettingsModal(true);" class="w-full py-1.5 px-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors cursor-pointer shadow-sm">
            <i data-lucide="plus" class="w-3.5 h-3.5"></i> Add New Profile
          </button>
        </div>
      `;

      menu.innerHTML = html;
      this.safeCreateIcons();
    },

    openSettingsModal(createNew = false) {
      const menu = document.getElementById('header-profile-menu');
      if (menu) menu.classList.add('hidden');

      const modal = document.getElementById('settings-modal');
      if (!modal) return;

      try {
        if (createNew) {
          this.create();
        } else {
          const active = this.getActive();
          this.selectedModalProfileId = active ? active.id : (this.getAll()[0]?.id || null);
          this.renderModal();
        }
      } catch (e) {
        console.error('Error preparing profiles modal:', e);
      }

      modal.classList.remove('hidden');
      modal.classList.add('flex');
      this._deleteSelection = {};
      this._catalogDeleteSelection = {};
      this.showProfileTab('mine');
      this.loadSharedCatalog();
    },

    showProfileTab(tab) {
      const names = ['mine', 'directory'];
      if (names.indexOf(tab) === -1) tab = 'mine';
      this.profileTab = tab;
      names.forEach((name) => {
        const panel = document.getElementById('profile-tab-' + name);
        const button = document.getElementById('profile-tab-btn-' + name);
        const on = name === tab;
        if (panel) {
          panel.classList.toggle('hidden', !on);
          panel.classList.toggle('flex', on);
        }
        if (button) {
          button.classList.toggle('bg-slate-700', on);
          button.classList.toggle('text-white', on);
          button.classList.toggle('text-slate-300', !on);
        }
      });
      if (tab === 'directory') this.loadSharedCatalog();
      this.safeCreateIcons();
    },

    async loadSharedCatalog() {
      if (!localStorage.getItem('auth_token')) {
        this._catalogRows = [];
        this._catalogMessage = 'Sign in to search the shared database.';
        this.renderTeamDirectory();
        return;
      }
      try {
        const data = await API.getProfileCatalog();
        this._catalogRows = data && Array.isArray(data.profiles) ? data.profiles : [];
        this._catalogMessage = this._catalogRows.length
          ? ''
          : 'No saved profiles are in this database yet. A teammate shows up after they sign in and save on a site that uses this same database. The test site does. Development and production do after their deploy buttons are played.';
      } catch (e) {
        this._catalogRows = [];
        this._catalogMessage = 'The shared database is unavailable right now.';
      }
      this.renderTeamDirectory();
    },

    renderTeamDirectory() {
      const el = document.getElementById('shared-profile-catalog');
      if (!el) return;
      const query = ((document.getElementById('team-profile-search') || {}).value || '').trim().toLowerCase();
      const me = localStorage.getItem('auth_username') || '';
      const rows = (this._catalogRows || []).filter((row) => {
        if (!query) return true;
        const haystack = [row.name, row.owner, row.llmModel, row.llmUrl].join(' ').toLowerCase();
        return haystack.indexOf(query) !== -1;
      });
      if (!rows.length) {
        el.innerHTML = '<p class="text-sm leading-relaxed text-slate-400">' + this.escapeHtml(
          query ? 'No profile matches that search.' : (this._catalogMessage || 'No saved profiles are in this database yet.')
        ) + '</p>';
        return;
      }
      el.innerHTML = rows.map((row) => {
        const mine = me && row.owner === me;
        const note = mine
          ? 'This is one of your saved profiles. You can delete it here or from My profiles.'
          : 'Endpoint and model only. Tokens and API keys stay with ' + (row.owner || 'the owner') + '.';
        const checked = !!(this._catalogDeleteSelection && this._catalogDeleteSelection[row.id]);
        const select = mine
          ? '<input type="checkbox" class="mt-1 w-3.5 h-3.5 rounded border-slate-600 bg-slate-900 shrink-0" ' + (checked ? 'checked ' : '') + 'title="Select for delete" onchange="window.profiles.toggleCatalogDeleteSelection(\'' + this.escapeHtml(row.id) + '\', this.checked)">'
          : '';
        const actions = mine
          ? '<div class="flex flex-col items-stretch gap-1.5 shrink-0">' +
              '<button type="button" class="px-2.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium" data-owner="' + this.escapeHtml(row.owner) + '" data-id="' + this.escapeHtml(row.id) + '" onclick="window.profiles.copySharedProfile(this)">Add another copy</button>' +
              '<button type="button" class="px-2.5 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 rounded-lg text-xs font-medium" onclick="window.profiles.delete(\'' + this.escapeHtml(row.id) + '\').then(function(ok){ if(ok) window.profiles.loadSharedCatalog(); })">Delete</button>' +
            '</div>'
          : '<button type="button" class="shrink-0 px-2.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium" data-owner="' + this.escapeHtml(row.owner) + '" data-id="' + this.escapeHtml(row.id) + '" onclick="window.profiles.copySharedProfile(this)">Add to my profiles</button>';
        return '<div class="flex items-start gap-3 p-3 rounded-xl border border-slate-700/70 bg-slate-900/40">' +
          select +
          '<div class="min-w-0 flex-1">' +
            '<div class="text-sm font-semibold text-slate-100 truncate">' + this.escapeHtml(row.name) + '</div>' +
            '<div class="text-xs text-slate-400 mt-0.5 truncate">' + this.escapeHtml(row.owner || 'Unknown person') + (mine ? ' · you' : '') + '</div>' +
            '<div class="text-[11px] text-slate-500 mt-1 truncate">' + this.escapeHtml(row.llmModel || 'No model') + ' · ' + this.escapeHtml(row.llmUrl || 'No endpoint') + '</div>' +
            '<div class="text-[11px] text-slate-500 mt-1">' + this.escapeHtml(note) + '</div>' +
          '</div>' +
          actions +
        '</div>';
      }).join('');
      this.updateBulkDeleteBar();
    },

    async copySharedProfile(button) {
      if (!button) return;
      const owner = button.getAttribute('data-owner');
      const profileId = button.getAttribute('data-id');
      if (!localStorage.getItem('auth_token')) {
        this.showToast('Sign in before copying a profile.');
        return;
      }
      try {
        const result = await API.copyCredentialProfile({ owner: owner, profileId: profileId });
        if (!result || result.unauthorized) return;
        this.applyServerDocument(result);
        const profiles = this.getAll();
        this.selectedModalProfileId = profiles.length ? profiles[profiles.length - 1].id : null;
        this.renderModal();
        this.showProfileTab('mine');
        this.loadSharedCatalog();
        this.showToast(result.conflict ? 'Your profiles changed on another site. Reloaded the shared copy.' : 'Added to your profiles.');
      } catch (e) {
        this.showToast(e.message || 'Could not copy that profile.');
      }
    },

    async deleteSharedProfiles() {
      if (!localStorage.getItem('auth_token')) {
        this.showToast('Sign in before deleting profiles.');
        return;
      }
      if (!window.confirm('Delete your profiles from test, development, and production?')) return;
      try {
        const result = await API.deleteCredentialProfiles();
        if (!result || result.unauthorized) return;
        this.applyServerDocument(result);
        this.selectedModalProfileId = null;
        this.renderModal();
        this.loadSharedCatalog();
        this.showToast('Your profiles were deleted on all sites.');
      } catch (e) {
        this.showToast(e.message || 'Could not delete profiles.');
      }
    },

    closeSettingsModal() {
      const modal = document.getElementById('settings-modal');
      if (!modal) return;
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    },

    renderModal() {
      const profiles = this.getAll();
      const activeId = this.getActiveId();

      if (!this.selectedModalProfileId || !profiles.some(p => p.id === this.selectedModalProfileId)) {
        this.selectedModalProfileId = activeId || (profiles[0] ? profiles[0].id : null);
      }

      const listContainer = document.getElementById('profiles-list-container');
      if (listContainer) {
        if (!profiles.length) {
          listContainer.innerHTML = '<p class="px-2 py-3 text-[11px] leading-relaxed text-slate-500">No profiles yet. Create one, or add a teammate profile from Team Profile Database.</p>';
        } else {
          listContainer.innerHTML = profiles.map(p => {
            const isSelected = p.id === this.selectedModalProfileId;
            const isActive = p.id === activeId;
            const checked = !!(this._deleteSelection && this._deleteSelection[p.id]);
            return `
              <div class="p-2.5 rounded-xl transition-all border ${isSelected ? 'bg-blue-600/15 border-blue-500/80 text-white shadow-sm ring-1 ring-blue-500/30' : 'bg-slate-900/40 border-slate-700/60 text-slate-300 hover:border-slate-500 hover:bg-slate-800/60'}">
                <div class="flex items-start gap-2">
                  <input type="checkbox" class="mt-0.5 w-3.5 h-3.5 rounded border-slate-600 bg-slate-900 shrink-0" ${checked ? 'checked' : ''} title="Select for delete" onclick="event.stopPropagation()" onchange="window.profiles.toggleDeleteSelection('${p.id}', this.checked)">
                  <div class="min-w-0 flex-1 cursor-pointer" onclick="window.profiles.selectProfileInModal('${p.id}')">
                    <div class="flex items-center justify-between gap-1 mb-1">
                      <span class="text-xs font-semibold truncate ${isSelected ? 'text-blue-400' : 'text-slate-200'}">${this.escapeHtml(p.name)}</span>
                      <div class="flex items-center gap-1 shrink-0">
                        ${p.isDefault ? '<span class="text-[9px] font-bold px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">DEFAULT</span>' : ''}
                        ${isActive ? '<span class="text-[9px] font-bold px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">ACTIVE</span>' : ''}
                      </div>
                    </div>
                    <div class="text-[10px] text-slate-400 font-mono truncate">${this.escapeHtml(p.llmModel || 'No model')}</div>
                  </div>
                </div>
                <div class="flex items-center justify-end gap-1 mt-2">
                  <button type="button" onclick="event.stopPropagation(); window.profiles.duplicate('${p.id}')" title="Duplicate profile" class="px-1.5 py-1 text-[10px] text-slate-400 hover:text-blue-300 rounded hover:bg-slate-700/70 flex items-center gap-1"><i data-lucide="copy" class="w-3 h-3"></i> Copy</button>
                  <button type="button" onclick="event.stopPropagation(); window.profiles.delete('${p.id}')" title="Delete profile" class="px-1.5 py-1 text-[10px] text-rose-300 hover:text-rose-200 rounded hover:bg-rose-500/10 flex items-center gap-1"><i data-lucide="trash-2" class="w-3 h-3"></i> Delete</button>
                </div>
              </div>
            `;
          }).join('');
        }
        this.updateBulkDeleteBar();
      }

      // Populate right-pane editor with selected profile
      const selected = profiles.find(p => p.id === this.selectedModalProfileId);
      const titleEl = document.getElementById('profile-editor-title');
      const statusBadge = document.getElementById('profile-editor-status');
      if (selected) {
        this.populateEditor(selected, activeId);
      } else if (titleEl) {
        titleEl.textContent = 'No profile selected';
        if (statusBadge) statusBadge.innerHTML = '';
        this.updateDefaultButton(false);
        ['profile-name-input', 'profile-jira-pat', 'profile-project-key', 'profile-llm-url', 'profile-llm-key', 'profile-llm-model', 'profile-collab-pat'].forEach((id) => {
          const input = document.getElementById(id);
          if (input) input.value = '';
        });
        const defaultChk = document.getElementById('profile-is-default-chk');
        if (defaultChk) defaultChk.checked = false;
      }

      this.safeCreateIcons();
    },

    selectProfileInModal(id) {
      this.selectedModalProfileId = id;
      this.renderModal();
    },

    populateEditor(p, activeId) {
      const nameInput = document.getElementById('profile-name-input');
      const patInput = document.getElementById('profile-jira-pat');
      const projectKeyInput = document.getElementById('profile-project-key');
      const urlInput = document.getElementById('profile-llm-url');
      const keyInput = document.getElementById('profile-llm-key');
      const modelInput = document.getElementById('profile-llm-model');
      const collabPatInput = document.getElementById('profile-collab-pat');
      const isDefaultCheckbox = document.getElementById('profile-is-default-chk');

      if (nameInput) nameInput.value = p.name || '';
      if (patInput) patInput.value = p.jiraPat || localStorage.getItem('jira_pat') || '';
      if (projectKeyInput) projectKeyInput.value = localStorage.getItem('jira_project_key') || 'SIGPOSDEV';
      if (urlInput) urlInput.value = p.llmUrl || '';
      if (keyInput) keyInput.value = p.llmKey || '';
      if (modelInput) modelInput.value = p.llmModel || '';
      if (collabPatInput) collabPatInput.value = p.collabPat || localStorage.getItem('collab_pat') || '';
      if (isDefaultCheckbox) isDefaultCheckbox.checked = !!p.isDefault;
      this.updateDefaultButton(!!p.isDefault);

      const titleEl = document.getElementById('profile-editor-title');
      if (titleEl) titleEl.textContent = p.name || 'Edit Profile';

      const statusBadge = document.getElementById('profile-editor-status');
      if (statusBadge) {
        const isActive = p.id === activeId;
        statusBadge.innerHTML = `
          ${p.isDefault ? '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500 text-slate-950 border border-amber-300 flex items-center gap-1">★ Default</span>' : ''}
          ${isActive ? '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Active in Portal</span>' : ''}
        `;
      }

      // Load per-user Bug Analyser settings from backend database
      if (typeof API !== 'undefined' && API.getBugWatchdogSettings) {
        API.getBugWatchdogSettings().then(cfg => {
          if (cfg) {
            const enEl = document.getElementById('user-bug-watchdog-enable');
            const prEl = document.getElementById('user-bug-watchdog-projects');
            const ipEl = document.getElementById('user-bug-watchdog-board-ip');
            const emEl = document.getElementById('user-bug-watchdog-email');
            const patEl = document.getElementById('profile-jira-pat');
            const urlEl = document.getElementById('profile-llm-url');
            const keyEl = document.getElementById('profile-llm-key');
            if (enEl) enEl.checked = !!cfg.is_enabled;
            if (prEl) prEl.value = cfg.jira_projects || '';
            if (ipEl) ipEl.value = cfg.target_board_ip || '';
            if (emEl) emEl.value = cfg.notify_email || '';
            if (patEl && !patEl.value && cfg.jira_pat) patEl.value = cfg.jira_pat;
            if (urlEl && !urlEl.value && cfg.llm_url) urlEl.value = cfg.llm_url;
            if (keyEl && !keyEl.value && cfg.llm_key) keyEl.value = cfg.llm_key;
            const bIpEl = document.getElementById('user-bug-watchdog-build-ip');
            const bRootEl = document.getElementById('user-bug-watchdog-build-root');
            if (bIpEl) bIpEl.value = cfg.build_server_ip || '';
            if (bRootEl) bRootEl.value = cfg.build_root_path || '';
            const uBadge = document.getElementById('current-user-badge');
            if (uBadge) {
              const uName = cfg.current_username || localStorage.getItem('gpos_user') || (window.auth && window.auth.user ? window.auth.user.username : '') || 'active user';
              uBadge.textContent = uName;
            }
          }
        }).catch(err => console.warn('Could not load bug watchdog settings:', err));
      }
    },

    async copyAgentPublicKey() {
      try {
        const token = localStorage.getItem('gpos_token') || localStorage.getItem('jwt_token') || '';
        const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
        const res = await fetch('/api/user/ssh-public-key', { headers });
        const data = await res.json();
        if (data && data.public_key) {
          await navigator.clipboard.writeText(data.public_key);
          this.showToast('✅ Agent SSH public key copied to clipboard! Paste into ~/.ssh/authorized_keys on your build machine.');
        } else {
          this.showToast('ℹ️ No standalone SSH public key file found on pod. Standard cluster lab keys are used.');
        }
      } catch (err) {
        this.showToast('Could not retrieve agent public key: ' + err.message);
      }
    },

    saveCurrentEditor(activateAfterSave = false) {
      if (!this.selectedModalProfileId) return;

      // Save per-user Bug Analyser settings and credentials to backend database
      const enEl = document.getElementById('user-bug-watchdog-enable');
      const prEl = document.getElementById('user-bug-watchdog-projects');
      const ipEl = document.getElementById('user-bug-watchdog-board-ip');
      const emEl = document.getElementById('user-bug-watchdog-email');
      const patEl = document.getElementById('profile-jira-pat');
      const urlEl = document.getElementById('profile-llm-url');
      const keyEl = document.getElementById('profile-llm-key');
      const activeProf = this.getActive();

      const patVal = (patEl ? patEl.value.trim() : '') || localStorage.getItem('jira_pat') || (activeProf ? activeProf.jiraPat : '') || '';
      const urlVal = (urlEl ? urlEl.value.trim() : '') || (activeProf ? activeProf.llmUrl : '') || 'http://exacode-chat.lge.com/v1';
      const keyVal = (keyEl ? keyEl.value.trim() : '') || localStorage.getItem('llm_key') || (activeProf ? activeProf.llmKey : '') || '';

      if (typeof API !== 'undefined' && API.saveBugWatchdogSettings && enEl) {
        API.saveBugWatchdogSettings({
          is_enabled: enEl.checked,
          jira_projects: prEl ? prEl.value.trim() : '',
          target_board_ip: ipEl ? ipEl.value.trim() : '',
          notify_email: emEl ? emEl.value.trim() : '',
          jira_pat: patVal,
          llm_url: urlVal,
          llm_key: keyVal,
          build_server_ip: (document.getElementById('user-bug-watchdog-build-ip') ? document.getElementById('user-bug-watchdog-build-ip').value.trim() : ''),
          build_root_path: (document.getElementById('user-bug-watchdog-build-root') ? document.getElementById('user-bug-watchdog-build-root').value.trim() : '')
        }).then(() => {
          if (typeof bugWatchdogPanel !== 'undefined' && bugWatchdogPanel.load) {
            setTimeout(() => bugWatchdogPanel.load(), 2000);
          }
        }).catch(err => console.warn('Could not save bug watchdog settings:', err));
      }

      const nameInput = document.getElementById('profile-name-input');
      const patInput = document.getElementById('profile-jira-pat');
      const projectKeyInput = document.getElementById('profile-project-key');
      const urlInput = document.getElementById('profile-llm-url');
      const keyInput = document.getElementById('profile-llm-key');
      const modelInput = document.getElementById('profile-llm-model');
      const collabPatInput = document.getElementById('profile-collab-pat');
      const isDefaultCheckbox = document.getElementById('profile-is-default-chk');

      const updatedData = {
        id: this.selectedModalProfileId,
        name: (nameInput ? nameInput.value : '').trim() || 'Untitled Profile',
        jiraPat: patInput ? patInput.value.trim() : '',
        llmUrl: urlInput ? urlInput.value.trim() : '',
        llmKey: keyInput ? keyInput.value.trim() : '',
        llmModel: modelInput ? modelInput.value.trim() : '',
        collabPat: collabPatInput ? collabPatInput.value.trim() : '',
        isDefault: isDefaultCheckbox ? isDefaultCheckbox.checked : false
      };

      this.save(updatedData);

      // Persist Jira PAT and Collab PAT globally to localStorage so all profiles & views have access
      if (updatedData.jiraPat) {
        localStorage.setItem('jira_pat', updatedData.jiraPat);
        // Also update all profiles in cache so switching profiles never clears Jira PAT
        const allProfs = this.getAll();
        allProfs.forEach(p => { if (!p.jiraPat) p.jiraPat = updatedData.jiraPat; });
        this.saveAll(allProfs);
      }
      if (updatedData.collabPat) {
        localStorage.setItem('collab_pat', updatedData.collabPat);
      }
      if (projectKeyInput && projectKeyInput.value.trim()) {
        const pk = projectKeyInput.value.trim().toUpperCase();
        localStorage.setItem('jira_project_key', pk);
        const headerInput = document.getElementById('header-project-key');
        if (headerInput) headerInput.value = pk;
        document.querySelectorAll('.project-name-display').forEach(el => el.textContent = pk);
      }

      if (activateAfterSave) {
        this.activate(this.selectedModalProfileId, true);
        this.closeSettingsModal();
      } else {
        this.syncToLegacyKeys(updatedData);
        this.refreshActiveSession();
      }
    },

    refreshActiveSession() {
      // Re-fetch user profile for header greeting
      if (typeof API !== 'undefined' && API.getUserProfile) {
        API.getUserProfile().then(user => {
          if (user && user.name) {
            const greetingEl = document.getElementById('user-greeting');
            if (greetingEl) {
              const hour = new Date().getHours();
              let greeting = "Good evening";
              if (hour < 12) greeting = "Good morning";
              else if (hour < 17) greeting = "Good afternoon";
              greetingEl.textContent = `${greeting}, ${user.name} / ${user.division} 👋`;
            }
            const profileNameEl = document.getElementById('sidebar-user-name');
            const profileInitialsEl = document.getElementById('sidebar-user-initials');
            if (profileNameEl) profileNameEl.textContent = user.name;
            if (profileInitialsEl) profileInitialsEl.textContent = user.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
          }
        }).catch(e => console.warn('Could not refresh user profile:', e));
      }
      // Re-fetch dashboard data
      if (typeof dashboard !== 'undefined' && typeof dashboard.loadData === 'function') {
        dashboard.loadData();
      }
    },

    togglePasswordVisibility(inputId, btnEl) {
      const input = document.getElementById(inputId);
      if (!input) return;
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      if (btnEl) {
        btnEl.innerHTML = isPassword ? '<i data-lucide="eye-off" class="w-4 h-4"></i>' : '<i data-lucide="eye" class="w-4 h-4"></i>';
        this.safeCreateIcons();
      }
    },

    showToast(msg) {
      const toast = document.getElementById('toast');
      const toastMsg = document.getElementById('toast-message');
      if (toastMsg) toastMsg.textContent = msg;
      if (toast) {
        toast.classList.remove('translate-y-[150%]', 'opacity-0');
        setTimeout(() => {
          toast.classList.add('translate-y-[150%]', 'opacity-0');
        }, 3000);
      }
    },

    escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },

    setupGlobalListeners() {
      // Close dropdown when clicking outside
      document.addEventListener('click', (e) => {
        const container = document.getElementById('header-profile-container');
        const menu = document.getElementById('header-profile-menu');
        if (container && menu && !container.contains(e.target)) {
          menu.classList.add('hidden');
        }
      });
    }
  };

  // Expose globally
  window.profiles = ProfilesManager;

  // Initialize on script load or DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => ProfilesManager.init());
  } else {
    ProfilesManager.init();
  }

  // Bind legacy toggleSettings to Profiles Manager modal
  window.toggleSettings = function () {
    const modal = document.getElementById('settings-modal');
    if (!modal) return;
    if (modal.classList.contains('hidden')) {
      ProfilesManager.openSettingsModal();
    } else {
      ProfilesManager.closeSettingsModal();
    }
  };
})();
