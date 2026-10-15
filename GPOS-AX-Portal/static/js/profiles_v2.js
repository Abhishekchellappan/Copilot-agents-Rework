/**
 * profiles_v2.js - Multi-Profile Manager for Credential & LLM Settings
 * Modeled after WinSCP / FileZilla Site Manager.
 * Supports multiple named profiles, default profile selection, instant switching, and presets.
 */

(function () {
  'use strict';

  const KEY_PROFILES = 'credential_profiles';
  const KEY_ACTIVE_ID = 'active_credential_profile_id';

  const ProfilesManager = {
    selectedModalProfileId: null,

    init() {
      this.migrateLegacyIfNeeded();
      const active = this.getActive();
      if (active) {
        this.syncToLegacyKeys(active);
      }
      this.updateHeaderProfileBadge();
      this.setupGlobalListeners();
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
        this.saveAll(profiles);
        localStorage.setItem(KEY_ACTIVE_ID, defaultProfile.id);
      } else {
        // Ensure at least one profile is default and active ID is valid
        let defaultExists = profiles.some(p => p.isDefault);
        if (!defaultExists && profiles.length > 0) {
          profiles[0].isDefault = true;
          this.saveAll(profiles);
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

    saveAll(profiles) {
      try {
        localStorage.setItem(KEY_PROFILES, JSON.stringify(profiles));
      } catch (e) {
        console.error('Failed to write profiles to localStorage', e);
      }
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
        if (profile.jiraPat !== undefined) localStorage.setItem('jira_pat', profile.jiraPat);
        if (profile.llmUrl !== undefined) localStorage.setItem('llm_api_url', profile.llmUrl);
        if (profile.llmKey !== undefined) localStorage.setItem('llm_api_key', profile.llmKey);
        if (profile.llmModel !== undefined) localStorage.setItem('llm_api_model', profile.llmModel);
        if (profile.collabPat !== undefined) localStorage.setItem('collab_pat', profile.collabPat);
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

      profiles.forEach(p => p.isDefault = (p.id === id));
      this.saveAll(profiles);
      this.renderModal();
      this.showToast(`"${target.name}" is now the default profile`);
    },

    activate(id, reloadPage = false) {
      const menu = document.getElementById('header-profile-menu');
      if (menu) menu.classList.add('hidden');

      const profile = this.get(id);
      if (!profile) return;

      localStorage.setItem(KEY_ACTIVE_ID, id);
      this.syncToLegacyKeys(profile);
      this.updateHeaderProfileBadge();
      this.renderModal();
      this.showToast(`Activated profile: "${profile.name}"`);

      if (reloadPage) {
        setTimeout(() => window.location.reload(), 300);
      }
    },

    delete(id) {
      let profiles = this.getAll();
      if (profiles.length <= 1) {
        alert("You must keep at least one profile.");
        return;
      }

      const target = profiles.find(p => p.id === id);
      if (!target) return;

      if (!confirm(`Are you sure you want to delete profile "${target.name}"?`)) {
        return;
      }

      profiles = profiles.filter(p => p.id !== id);

      // If deleted profile was default, make the first remaining profile default
      if (target.isDefault && profiles.length > 0) {
        profiles[0].isDefault = true;
      }

      // If deleted profile was active, activate default
      const wasActive = this.getActiveId() === id;
      if (wasActive && profiles.length > 0) {
        const nextActive = profiles.find(p => p.isDefault) || profiles[0];
        localStorage.setItem(KEY_ACTIVE_ID, nextActive.id);
        this.syncToLegacyKeys(nextActive);
      }

      this.saveAll(profiles);
      this.selectedModalProfileId = profiles[0].id;
      this.updateHeaderProfileBadge();
      this.renderModal();
      this.showToast(`Deleted profile "${target.name}"`);
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
        listContainer.innerHTML = profiles.map(p => {
          const isSelected = p.id === this.selectedModalProfileId;
          const isActive = p.id === activeId;
          return `
            <div onclick="window.profiles.selectProfileInModal('${p.id}')" class="p-2.5 rounded-xl cursor-pointer transition-all border ${isSelected ? 'bg-blue-600/15 border-blue-500/80 text-white shadow-sm ring-1 ring-blue-500/30' : 'bg-slate-900/40 border-slate-700/60 text-slate-300 hover:border-slate-500 hover:bg-slate-800/60'} group">
              <div class="flex items-center justify-between gap-1 mb-1">
                <span class="text-xs font-semibold truncate ${isSelected ? 'text-blue-400' : 'text-slate-200'}">${this.escapeHtml(p.name)}</span>
                <div class="flex items-center gap-1 shrink-0">
                  ${p.isDefault ? '<span class="text-[9px] font-bold px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">DEFAULT</span>' : ''}
                  ${isActive ? '<span class="text-[9px] font-bold px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">ACTIVE</span>' : ''}
                </div>
              </div>
              <div class="flex items-center justify-between text-[11px] text-slate-400">
                <span class="truncate max-w-[130px] font-mono text-[10px] text-slate-400">${this.escapeHtml(p.llmModel || 'No model')}</span>
                <div class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button type="button" onclick="event.stopPropagation(); window.profiles.duplicate('${p.id}')" title="Duplicate profile" class="p-1 hover:text-blue-400 rounded"><i data-lucide="copy" class="w-3 h-3"></i></button>
                  ${profiles.length > 1 ? `<button type="button" onclick="event.stopPropagation(); window.profiles.delete('${p.id}')" title="Delete profile" class="p-1 hover:text-red-400 rounded"><i data-lucide="trash-2" class="w-3 h-3"></i></button>` : ''}
                </div>
              </div>
            </div>
          `;
        }).join('');
      }

      // Populate right-pane editor with selected profile
      const selected = profiles.find(p => p.id === this.selectedModalProfileId);
      if (selected) {
        this.populateEditor(selected, activeId);
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
      const urlInput = document.getElementById('profile-llm-url');
      const keyInput = document.getElementById('profile-llm-key');
      const modelInput = document.getElementById('profile-llm-model');
      const collabPatInput = document.getElementById('profile-collab-pat');
      const isDefaultCheckbox = document.getElementById('profile-is-default-chk');

      if (nameInput) nameInput.value = p.name || '';
      if (patInput) patInput.value = p.jiraPat || '';
      if (urlInput) urlInput.value = p.llmUrl || '';
      if (keyInput) keyInput.value = p.llmKey || '';
      if (modelInput) modelInput.value = p.llmModel || '';
      if (collabPatInput) collabPatInput.value = p.collabPat || '';
      if (isDefaultCheckbox) isDefaultCheckbox.checked = !!p.isDefault;

      const titleEl = document.getElementById('profile-editor-title');
      if (titleEl) titleEl.textContent = p.name || 'Edit Profile';

      const statusBadge = document.getElementById('profile-editor-status');
      if (statusBadge) {
        const isActive = p.id === activeId;
        statusBadge.innerHTML = `
          ${p.isDefault ? '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1">★ Default Profile</span>' : ''}
          ${isActive ? '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Active in Portal</span>' : ''}
        `;
      }
    },

    saveCurrentEditor(activateAfterSave = false) {
      if (!this.selectedModalProfileId) return;

      const nameInput = document.getElementById('profile-name-input');
      const patInput = document.getElementById('profile-jira-pat');
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

      if (activateAfterSave) {
        this.activate(this.selectedModalProfileId, false);
        this.closeSettingsModal();
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
