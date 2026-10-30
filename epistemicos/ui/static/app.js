/**
 * EpistemicOS Control Plane Observatory - Client Application.
 *
 * Implements read-only client dashboard interface for:
 * 1. System Overview Metrics & Integrity Status
 * 2. Execution Trace Explorer & Evidence Inspector
 * 3. Provenance Chain Explorer
 * 4. Benchmark Workbench
 *
 * Security Directive: All dynamic data rendering strictly uses textContent
 * and standard DOM element creation to eliminate XSS risks from untrusted event payloads.
 */

document.addEventListener('DOMContentLoaded', () => {
  const ObservatoryApp = {
    state: {
      currentTab: 'overview',
      overviewData: null,
      tracesData: [],
      selectedTraceId: null,
      selectedEventSeq: null,
      provenanceData: null,
      selectedRecordId: null,
      benchmarkData: null,
      traceFilterStatus: 'ALL',
      traceSearchQuery: '',
      provenanceFilterType: 'ALL',
      provenanceSearchQuery: '',
      selectedCaseIndex: null,
      caseSearchQuery: '',
      caseBaselineFilter: 'ALL',
      caseOutcomeFilter: 'ALL'
    },

    init() {
      this.bindEvents();
      this.loadOverview();
    },

    bindEvents() {
      // Primary Tab Navigation
      const tabs = Array.from(document.querySelectorAll('.nav-tab'));
      tabs.forEach((tabBtn, index) => {
        tabBtn.addEventListener('click', (e) => {
          const tabName = e.currentTarget.getAttribute('data-tab');
          this.switchTab(tabName);
        });

        tabBtn.addEventListener('keydown', (e) => {
          let targetIndex = null;
          if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
            targetIndex = (index + 1) % tabs.length;
          } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
            targetIndex = (index - 1 + tabs.length) % tabs.length;
          } else if (e.key === 'Home') {
            targetIndex = 0;
          } else if (e.key === 'End') {
            targetIndex = tabs.length - 1;
          }

          if (targetIndex !== null) {
            e.preventDefault();
            const targetTab = tabs[targetIndex];
            const tabName = targetTab.getAttribute('data-tab');
            this.switchTab(tabName);
            targetTab.focus();
          }
        });
      });

      // Quick Entry / Investigative Shortcuts Navigation
      document.querySelectorAll('[data-jump-tab]').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const targetTab = e.currentTarget.getAttribute('data-jump-tab');
          const filter = e.currentTarget.getAttribute('data-filter');

          if (filter && targetTab === 'traces') {
            this.state.traceFilterStatus = filter;
            const filterSelect = document.getElementById('trace-status-filter');
            if (filterSelect) filterSelect.value = filter;
          }
          this.switchTab(targetTab);
        });
      });

      // Overview Refresh
      const btnRefreshOverview = document.getElementById('btn-refresh-overview');
      if (btnRefreshOverview) {
        btnRefreshOverview.addEventListener('click', () => this.loadOverview());
      }

      // Execution Trace Search & Filters
      const searchInput = document.getElementById('trace-search');
      if (searchInput) {
        searchInput.addEventListener('input', (e) => {
          this.state.traceSearchQuery = e.target.value.toLowerCase().trim();
          this.renderTracesList();
        });
        searchInput.addEventListener('keydown', (e) => {
          if (e.key === 'Escape') {
            if (searchInput.value) {
              searchInput.value = '';
              this.state.traceSearchQuery = '';
              this.renderTracesList();
            } else {
              searchInput.blur();
            }
          }
        });
      }

      const statusFilter = document.getElementById('trace-status-filter');
      if (statusFilter) {
        statusFilter.addEventListener('change', (e) => {
          this.state.traceFilterStatus = e.target.value;
          this.renderTracesList();
        });
      }

      // Provenance Search & Filter Controls
      const provSearchInput = document.getElementById('provenance-search');
      if (provSearchInput) {
        provSearchInput.addEventListener('input', (e) => {
          this.state.provenanceSearchQuery = e.target.value.toLowerCase().trim();
          this.renderProvenanceRecordList();
        });
        provSearchInput.addEventListener('keydown', (e) => {
          if (e.key === 'Escape') {
            if (provSearchInput.value) {
              provSearchInput.value = '';
              this.state.provenanceSearchQuery = '';
              this.renderProvenanceRecordList();
            } else {
              provSearchInput.blur();
            }
          }
        });
      }

      const provTypeFilter = document.getElementById('provenance-type-filter');
      if (provTypeFilter) {
        provTypeFilter.addEventListener('change', (e) => {
          this.state.provenanceFilterType = e.target.value;
          this.renderProvenanceRecordList();
        });
      }

      // Benchmark Workbench Filter Controls
      const caseSearchInput = document.getElementById('benchmark-case-search');
      if (caseSearchInput) {
        caseSearchInput.addEventListener('input', (e) => {
          this.state.caseSearchQuery = e.target.value.toLowerCase().trim();
          this.renderBenchmarkCasesList();
        });
        caseSearchInput.addEventListener('keydown', (e) => {
          if (e.key === 'Escape') {
            if (caseSearchInput.value) {
              caseSearchInput.value = '';
              this.state.caseSearchQuery = '';
              this.renderBenchmarkCasesList();
            } else {
              caseSearchInput.blur();
            }
          }
        });
      }

      const caseBaseFilterSelect = document.getElementById('benchmark-case-baseline-filter');
      if (caseBaseFilterSelect) {
        caseBaseFilterSelect.addEventListener('change', (e) => {
          this.state.caseBaselineFilter = e.target.value;
          this.renderBenchmarkCasesList();
        });
      }

      const caseOutcomeFilterSelect = document.getElementById('benchmark-case-outcome-filter');
      if (caseOutcomeFilterSelect) {
        caseOutcomeFilterSelect.addEventListener('change', (e) => {
          this.state.caseOutcomeFilter = e.target.value;
          this.renderBenchmarkCasesList();
        });
      }

      // Global Keyboard Shortcut: '/' to focus active tab search input
      document.addEventListener('keydown', (e) => {
        if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
          let searchInput = null;
          if (this.state.currentTab === 'traces') searchInput = document.getElementById('trace-search');
          else if (this.state.currentTab === 'provenance') searchInput = document.getElementById('provenance-search');
          else if (this.state.currentTab === 'benchmarks') searchInput = document.getElementById('benchmark-case-search');

          if (searchInput) {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
          }
        }
      });
    },

    switchTab(tabName) {
      this.state.currentTab = tabName;
      document.querySelectorAll('.nav-tab').forEach(btn => {
        const isActive = btn.getAttribute('data-tab') === tabName;
        btn.classList.toggle('active', isActive);
        btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
        btn.setAttribute('tabindex', isActive ? '0' : '-1');

        if (isActive && typeof btn.scrollIntoView === 'function') {
          btn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
        }
      });

      const tabTitles = {
        overview: 'System Executive Overview',
        traces: 'Execution Trace Explorer',
        provenance: 'Provenance Explorer',
        benchmarks: 'Benchmark Workbench'
      };
      const mobileTitleEl = document.getElementById('mobile-current-title');
      if (mobileTitleEl) {
        mobileTitleEl.textContent = tabTitles[tabName] || tabName;
      }

      document.querySelectorAll('.view-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === `view-${tabName}`);
      });

      if (tabName === 'overview') this.loadOverview();
      else if (tabName === 'traces') this.loadTraces();
      else if (tabName === 'provenance') this.loadProvenance();
      else if (tabName === 'benchmarks') this.loadBenchmarks();
    },

    // -------------------------------------------------------------------------
    // Helper: Clipboard Copy Action
    // -------------------------------------------------------------------------
    copyToClipboard(text, btnElement) {
      if (!text) return;
      const origAriaLabel = btnElement ? btnElement.getAttribute('aria-label') : null;
      const origTitle = btnElement ? btnElement.getAttribute('title') : null;

      const restoreState = (origText) => {
        if (!btnElement) return;
        btnElement.textContent = origText;
        if (origAriaLabel !== null) {
          btnElement.setAttribute('aria-label', origAriaLabel);
        } else {
          btnElement.removeAttribute('aria-label');
        }
        if (origTitle !== null) {
          btnElement.setAttribute('title', origTitle);
        } else {
          btnElement.removeAttribute('title');
        }
      };

      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        if (btnElement) {
          const origText = btnElement.textContent;
          btnElement.textContent = 'Copy Unavailable';
          btnElement.setAttribute('aria-label', 'Copy unavailable');
          btnElement.setAttribute('title', 'Copy unavailable in this browser context');
          btnElement.style.borderColor = 'var(--status-failed-border)';
          setTimeout(() => {
            restoreState(origText);
            btnElement.style.borderColor = '';
          }, 2000);
        }
        return;
      }

      navigator.clipboard.writeText(text).then(() => {
        if (btnElement) {
          const origText = btnElement.textContent;
          btnElement.textContent = '✓ Copied!';
          btnElement.setAttribute('aria-label', 'Copied to clipboard!');
          btnElement.setAttribute('title', 'Copied to clipboard!');
          btnElement.classList.add('copied');
          setTimeout(() => {
            restoreState(origText);
            btnElement.classList.remove('copied');
          }, 1500);
        }
      }).catch(err => {
        console.error('Copy failed:', err);
        if (btnElement) {
          const origText = btnElement.textContent;
          btnElement.textContent = 'Copy Failed';
          btnElement.setAttribute('aria-label', 'Copy failed');
          btnElement.setAttribute('title', 'Copy action failed');
          btnElement.style.borderColor = 'var(--status-failed-border)';
          setTimeout(() => {
            restoreState(origText);
            btnElement.style.borderColor = '';
          }, 2000);
        }
      });
    },

    // Helper: Semantic Badge Creator
    createStatusBadge(statusText) {
      const span = document.createElement('span');
      const st = (statusText || 'UNKNOWN').toUpperCase();

      if (st === 'VERIFIED') {
        span.className = 'status-badge status-badge-verified';
        span.textContent = '✓ VERIFIED';
      } else if (st === 'FAILED' || st === 'FAIL') {
        span.className = 'status-badge status-badge-failed';
        span.textContent = '✗ FAILED';
      } else if (st === 'HALTED') {
        span.className = 'status-badge status-badge-halted';
        span.textContent = '🛑 HALTED';
      } else if (st === 'PENDING') {
        span.className = 'status-badge status-badge-pending';
        span.textContent = '⏳ PENDING';
      } else if (st === 'UNAVAILABLE') {
        span.className = 'status-badge status-badge-unavailable';
        span.textContent = '⊘ UNAVAILABLE';
      } else if (st === 'PARTIAL') {
        span.className = 'status-badge status-badge-partial';
        span.textContent = '⚠ PARTIAL';
      } else if (st === 'UNREADABLE') {
        span.className = 'status-badge status-badge-unreadable';
        span.textContent = '⊘ UNREADABLE';
      } else if (st === 'NOT ESTABLISHED') {
        span.className = 'status-badge status-badge-not-established';
        span.textContent = '░ NOT ESTABLISHED';
      } else {
        span.className = 'status-badge status-badge-unknown';
        span.textContent = `? ${st}`;
      }
      return span;
    },

    // -------------------------------------------------------------------------
    // View 1: Overview
    // -------------------------------------------------------------------------
    async loadOverview() {
      const btnRefresh = document.getElementById('btn-refresh-overview');
      const refreshIcon = btnRefresh ? btnRefresh.querySelector('.refresh-icon') : null;

      if (btnRefresh) {
        btnRefresh.disabled = true;
        btnRefresh.setAttribute('aria-busy', 'true');
        btnRefresh.setAttribute('title', 'Refreshing overview metrics...');
      }
      if (refreshIcon) {
        refreshIcon.classList.add('spin');
      }

      try {
        const [overviewRes, tracesRes] = await Promise.all([
          fetch('/api/overview'),
          fetch('/api/traces').catch(() => null)
        ]);

        if (!overviewRes.ok) throw new Error(`HTTP error ${overviewRes.status}`);
        const data = await overviewRes.json();
        this.state.overviewData = data;

        if (tracesRes && tracesRes.ok) {
          this.state.tracesData = await tracesRes.json();
        }

        this.renderOverview();
      } catch (err) {
        console.error('Failed to load overview:', err);
        this.renderOverviewError(err.message);
      } finally {
        if (btnRefresh) {
          btnRefresh.disabled = false;
          btnRefresh.removeAttribute('aria-busy');
          btnRefresh.setAttribute('title', 'Refresh overview metrics');
        }
        if (refreshIcon) {
          refreshIcon.classList.remove('spin');
        }
      }
    },

    renderOverview() {
      const data = this.state.overviewData;
      if (!data) return;

      const updatedEl = document.getElementById('overview-last-updated');
      if (updatedEl) {
        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        updatedEl.textContent = `Updated at ${timeStr}`;
      }

      const m = data.metrics || {};
      this.setText('metric-total-executions', (m.total_executions !== null && m.total_executions !== undefined) ? m.total_executions : 'UNAVAILABLE');
      this.setText('metric-denials', (m.authorization_denials !== null && m.authorization_denials !== undefined) ? m.authorization_denials : 'UNAVAILABLE');
      this.setText('metric-halts', (m.halts !== null && m.halts !== undefined) ? m.halts : 'UNAVAILABLE');
      this.setText('metric-failures', (m.execution_failures !== null && m.execution_failures !== undefined) ? m.execution_failures : 'UNAVAILABLE');
      this.setText('metric-parse-errors', (m.parse_error_count !== null && m.parse_error_count !== undefined) ? m.parse_error_count : 'UNAVAILABLE');

      const sf = data.status_flags || {};

      // Audit Data Availability Badge
      const auditAvailEl = document.getElementById('audit-data-availability');
      if (auditAvailEl) {
        const isAvail = sf.audit_data_available;
        auditAvailEl.className = isAvail ? 'status-badge status-badge-verified' : 'status-badge status-badge-unavailable';
        auditAvailEl.textContent = isAvail ? '✓ DATA AVAILABLE' : '⊘ DATA UNAVAILABLE';
      }

      // Audit Integrity Block
      const auditContainer = document.getElementById('audit-integrity-status');
      if (auditContainer) {
        auditContainer.innerHTML = '';
        const ai = data.audit_integrity || {};

        const headerDiv = document.createElement('div');
        headerDiv.style.display = 'flex';
        headerDiv.style.justifyContent = 'space-between';
        headerDiv.style.alignItems = 'center';
        headerDiv.style.marginBottom = '0.5rem';

        const labelSpan = document.createElement('span');
        labelSpan.style.fontWeight = '600';
        labelSpan.textContent = 'Integrity Verification: ';

        const badge = this.createStatusBadge(ai.status || 'UNAVAILABLE');
        headerDiv.appendChild(labelSpan);
        headerDiv.appendChild(badge);

        const msgDiv = document.createElement('div');
        msgDiv.className = 'text-muted';
        msgDiv.style.fontSize = '0.8rem';
        msgDiv.style.marginTop = '0.35rem';
        msgDiv.textContent = `Verification Message: ${ai.message || 'No audit records verified.'}`;

        const countDiv = document.createElement('div');
        countDiv.className = 'text-muted font-mono';
        countDiv.style.fontSize = '0.8rem';
        countDiv.style.marginTop = '0.2rem';
        countDiv.textContent = `Verified Entries: ${ai.records_verified ?? 0}`;

        auditContainer.appendChild(headerDiv);
        auditContainer.appendChild(msgDiv);
        auditContainer.appendChild(countDiv);
      }

      // Provenance Data Availability Badge
      const provAvailEl = document.getElementById('provenance-data-availability');
      if (provAvailEl) {
        const isAvail = sf.provenance_data_available;
        provAvailEl.className = isAvail ? 'status-badge status-badge-verified' : 'status-badge status-badge-unavailable';
        provAvailEl.textContent = isAvail ? '✓ DATA AVAILABLE' : '⊘ DATA UNAVAILABLE';
      }

      // Provenance Integrity Block
      const provContainer = document.getElementById('provenance-integrity-status');
      if (provContainer) {
        provContainer.innerHTML = '';
        const pi = data.provenance_integrity || {};

        const headerDiv = document.createElement('div');
        headerDiv.style.display = 'flex';
        headerDiv.style.justifyContent = 'space-between';
        headerDiv.style.alignItems = 'center';
        headerDiv.style.marginBottom = '0.5rem';

        const labelSpan = document.createElement('span');
        labelSpan.style.fontWeight = '600';
        labelSpan.textContent = 'Integrity Verification: ';

        const badge = this.createStatusBadge(pi.status || 'UNAVAILABLE');
        headerDiv.appendChild(labelSpan);
        headerDiv.appendChild(badge);

        const msgDiv = document.createElement('div');
        msgDiv.className = 'text-muted';
        msgDiv.style.fontSize = '0.8rem';
        msgDiv.style.marginTop = '0.35rem';
        msgDiv.textContent = `Verification Details: ${pi.message || 'No provenance events found.'}`;

        const countDiv = document.createElement('div');
        countDiv.className = 'text-muted font-mono';
        countDiv.style.fontSize = '0.8rem';
        countDiv.style.marginTop = '0.2rem';
        countDiv.textContent = `Verified Records: ${pi.records_verified ?? 0}`;

        provContainer.appendChild(headerDiv);
        provContainer.appendChild(msgDiv);
        provContainer.appendChild(countDiv);

        if (pi.last_hash) {
          const hashDiv = document.createElement('div');
          hashDiv.className = 'font-mono text-dim';
          hashDiv.style.fontSize = '0.75rem';
          hashDiv.style.marginTop = '0.4rem';
          hashDiv.style.wordBreak = 'break-all';
          hashDiv.textContent = `Tail Hash: ${pi.last_hash}`;
          provContainer.appendChild(hashDiv);
        }
      }

      // Render Overview Recent Traces
      this.renderOverviewRecentTraces();
    },

    renderOverviewRecentTraces() {
      const tbody = document.getElementById('overview-recent-traces');
      if (!tbody) return;

      tbody.innerHTML = '';
      const traces = this.state.tracesData || [];

      if (traces.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 5;
        td.className = 'text-center text-muted';
        td.textContent = 'No recent execution traces recorded.';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      // Show top 5 recent execution traces
      const recent = traces.slice(0, 5);

      recent.forEach(trace => {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.setAttribute('tabindex', '0');
        tr.setAttribute('role', 'button');
        tr.setAttribute('aria-label', `Inspect execution trace ${trace.correlation_id || 'UNKNOWN'}`);

        const handleActivate = () => {
          this.state.selectedTraceId = trace.correlation_id;
          this.switchTab('traces');
          this.selectTrace(trace.correlation_id);
        };

        tr.addEventListener('click', handleActivate);
        tr.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            handleActivate();
          }
        });

        const tdCorr = document.createElement('td');
        tdCorr.className = 'font-mono';
        tdCorr.style.fontSize = '0.775rem';
        tdCorr.textContent = (trace.correlation_id || '').length > 20 ? (trace.correlation_id || '').substring(0, 18) + '...' : (trace.correlation_id || 'UNKNOWN');
        tdCorr.title = trace.correlation_id;

        const tdAction = document.createElement('td');
        tdAction.textContent = trace.action_name || 'N/A';

        const tdTarget = document.createElement('td');
        tdTarget.textContent = trace.target || 'N/A';

        const tdStatus = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = `badge badge-${trace.status || 'OUTCOME_UNKNOWN'}`;
        badge.textContent = trace.status || 'UNKNOWN';
        tdStatus.appendChild(badge);

        const tdTime = document.createElement('td');
        tdTime.className = 'font-mono';
        tdTime.style.fontSize = '0.75rem';
        tdTime.textContent = trace.start_time || trace.timestamp || 'N/A';

        tr.appendChild(tdCorr);
        tr.appendChild(tdAction);
        tr.appendChild(tdTarget);
        tr.appendChild(tdStatus);
        tr.appendChild(tdTime);

        tbody.appendChild(tr);
      });
    },

    renderOverviewError(msg) {
      this.setText('metric-total-executions', 'ERROR');
      this.setText('metric-denials', 'ERROR');
      this.setText('metric-halts', 'ERROR');
      this.setText('metric-failures', 'ERROR');

      const updatedEl = document.getElementById('overview-last-updated');
      if (updatedEl) {
        updatedEl.textContent = 'Update failed';
      }
    },

    // -------------------------------------------------------------------------
    // View 2: Execution Trace Explorer
    // -------------------------------------------------------------------------
    async loadTraces() {
      const traceListUl = document.getElementById('trace-list');
      if (traceListUl && this.state.tracesData.length === 0) {
        traceListUl.innerHTML = '<li class="text-muted text-center" style="padding: 1.5rem;">Loading execution traces...</li>';
      }

      try {
        const res = await fetch('/api/traces');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        this.state.tracesData = Array.isArray(data) ? data : [];
        this.renderTracesList();
      } catch (err) {
        console.error('Failed to load traces:', err);
        this.renderTracesLoadError(err.message);
      }
    },

    renderTracesLoadError(errorMsg) {
      const traceListUl = document.getElementById('trace-list');
      if (!traceListUl) return;
      traceListUl.innerHTML = '';

      const errLi = document.createElement('li');
      errLi.className = 'text-danger text-center';
      errLi.style.padding = '1.5rem 1rem';

      const msgSpan = document.createElement('span');
      msgSpan.style.display = 'block';
      msgSpan.style.marginBottom = '0.5rem';
      msgSpan.style.fontWeight = '600';
      msgSpan.textContent = 'Failed to load execution traces.';

      const detailSpan = document.createElement('span');
      detailSpan.className = 'text-muted font-mono';
      detailSpan.style.fontSize = '0.75rem';
      detailSpan.style.display = 'block';
      detailSpan.style.marginBottom = '0.75rem';
      detailSpan.textContent = `Server API Error: ${errorMsg}`;

      const retryBtn = document.createElement('button');
      retryBtn.type = 'button';
      retryBtn.className = 'btn-refresh';
      retryBtn.textContent = 'Retry Loading Traces';
      retryBtn.setAttribute('aria-label', 'Retry loading execution traces');
      retryBtn.setAttribute('title', 'Retry loading execution traces');
      retryBtn.addEventListener('click', () => this.loadTraces());

      errLi.appendChild(msgSpan);
      errLi.appendChild(detailSpan);
      errLi.appendChild(retryBtn);
      traceListUl.appendChild(errLi);

      const countBadge = document.getElementById('trace-count');
      if (countBadge) {
        countBadge.textContent = 'ERROR';
      }
    },

    renderTracesList() {
      const traceListUl = document.getElementById('trace-list');
      if (!traceListUl) return;
      traceListUl.innerHTML = '';

      let filtered = this.state.tracesData.filter(t => {
        if (this.state.traceFilterStatus !== 'ALL' && t.status !== this.state.traceFilterStatus) {
          return false;
        }
        if (this.state.traceSearchQuery) {
          const q = this.state.traceSearchQuery;
          const corr = (t.correlation_id || '').toLowerCase();
          const req = (t.request_id || '').toLowerCase();
          const act = (t.action_name || '').toLowerCase();
          const tgt = (t.target || '').toLowerCase();
          return corr.includes(q) || req.includes(q) || act.includes(q) || tgt.includes(q);
        }
        return true;
      });

      const countBadge = document.getElementById('trace-count');
      if (countBadge) {
        const total = this.state.tracesData.length;
        const visible = filtered.length;
        countBadge.textContent = total === visible ? `${total}` : `${visible} of ${total}`;
        countBadge.setAttribute('aria-label', total === visible ? `${total} traces` : `${visible} of ${total} traces shown`);
      }

      if (filtered.length === 0) {
        const emptyLi = document.createElement('li');
        emptyLi.className = 'text-muted text-center';
        emptyLi.style.padding = '1.5rem 1rem';

        const hasFilters = this.state.traceSearchQuery || this.state.traceFilterStatus !== 'ALL';
        if (hasFilters) {
          const msgSpan = document.createElement('span');
          msgSpan.style.display = 'block';
          msgSpan.style.marginBottom = '0.5rem';
          msgSpan.textContent = 'No execution traces match active filter query.';

          const clearBtn = document.createElement('button');
          clearBtn.type = 'button';
          clearBtn.className = 'btn-refresh';
          clearBtn.textContent = 'Clear Filters';
          clearBtn.setAttribute('aria-label', 'Clear search query and status filter');
          clearBtn.setAttribute('title', 'Clear active search query and status filter');
          clearBtn.addEventListener('click', () => {
            this.state.traceSearchQuery = '';
            this.state.traceFilterStatus = 'ALL';
            const searchInput = document.getElementById('trace-search');
            if (searchInput) {
              searchInput.value = '';
              searchInput.focus();
            }
            const statusFilter = document.getElementById('trace-status-filter');
            if (statusFilter) statusFilter.value = 'ALL';
            this.renderTracesList();
          });

          emptyLi.appendChild(msgSpan);
          emptyLi.appendChild(clearBtn);
        } else {
          emptyLi.textContent = 'No execution traces recorded in local provenance or audit log.';
        }

        traceListUl.appendChild(emptyLi);
        return;
      }

      filtered.forEach((trace, index) => {
        const isSelected = this.state.selectedTraceId === trace.correlation_id;
        const li = document.createElement('li');
        li.className = `trace-item ${isSelected ? 'active' : ''}`;
        li.setAttribute('role', 'option');
        li.setAttribute('tabindex', '0');
        li.setAttribute('aria-selected', isSelected ? 'true' : 'false');
        li.setAttribute('aria-label', `Execution trace ${trace.correlation_id}, status ${trace.status}`);

        li.addEventListener('click', () => this.selectTrace(trace.correlation_id));
        li.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            this.selectTrace(trace.correlation_id);
          } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            const items = traceListUl.querySelectorAll('.trace-item');
            if (index + 1 < items.length) {
              items[index + 1].focus();
            }
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            const items = traceListUl.querySelectorAll('.trace-item');
            if (index - 1 >= 0) {
              items[index - 1].focus();
            }
          } else if (e.key === 'Home') {
            e.preventDefault();
            const items = traceListUl.querySelectorAll('.trace-item');
            if (items.length > 0) items[0].focus();
          } else if (e.key === 'End') {
            e.preventDefault();
            const items = traceListUl.querySelectorAll('.trace-item');
            if (items.length > 0) items[items.length - 1].focus();
          }
        });

        const headerDiv = document.createElement('div');
        headerDiv.className = 'trace-item-header';

        const idSpan = document.createElement('span');
        idSpan.className = 'trace-id';
        const displayCorr = trace.correlation_id ? (trace.correlation_id.length > 20 ? trace.correlation_id.substring(0, 18) + '...' : trace.correlation_id) : 'UNKNOWN';
        idSpan.textContent = displayCorr;
        idSpan.title = trace.correlation_id;

        const badgeSpan = document.createElement('span');
        badgeSpan.className = `badge badge-${trace.status || 'OUTCOME_UNKNOWN'}`;
        badgeSpan.textContent = trace.status || 'UNKNOWN';

        headerDiv.appendChild(idSpan);
        headerDiv.appendChild(badgeSpan);

        const subDiv = document.createElement('div');
        subDiv.className = 'text-muted';
        subDiv.style.fontSize = '0.75rem';
        subDiv.style.marginTop = '0.2rem';
        subDiv.textContent = `${trace.action_name || 'N/A'} ➔ ${trace.target || 'N/A'}`;

        const timeDiv = document.createElement('div');
        timeDiv.className = 'font-mono text-dim';
        timeDiv.style.fontSize = '0.7rem';
        timeDiv.style.marginTop = '0.15rem';
        timeDiv.textContent = trace.start_time || trace.timestamp || 'Timestamp unavailable';

        li.appendChild(headerDiv);
        li.appendChild(subDiv);
        li.appendChild(timeDiv);
        traceListUl.appendChild(li);
      });
    },

    async selectTrace(correlationId) {
      this.state.selectedTraceId = correlationId;
      this.state.selectedEventSeq = null;
      this.renderTracesList();

      const emptyDiv = document.getElementById('trace-detail-empty');
      const contentDiv = document.getElementById('trace-detail-content');

      if (!correlationId) {
        if (emptyDiv) emptyDiv.classList.remove('hidden');
        if (contentDiv) contentDiv.classList.add('hidden');
        return;
      }

      // Fetch trace detail
      try {
        const res = await fetch(`/api/trace/${encodeURIComponent(correlationId)}`);
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const trace = await res.json();

        if (emptyDiv) emptyDiv.classList.add('hidden');
        if (contentDiv) {
          contentDiv.classList.remove('hidden');
          this.renderTraceDetail(trace, contentDiv);
        }
      } catch (err) {
        console.error('Failed to load trace detail:', err);
        if (contentDiv) {
          contentDiv.classList.remove('hidden');
          this.renderTraceErrorDetail(correlationId, err.message, contentDiv);
        }
      }
    },

    renderTraceErrorDetail(correlationId, errorMsg, container) {
      container.innerHTML = '';

      const errCard = document.createElement('div');
      errCard.className = 'card';

      const errHeader = document.createElement('div');
      errHeader.className = 'card-header text-danger';
      errHeader.textContent = 'Execution Trace Fetch Failure';

      const h3 = document.createElement('h3');
      h3.textContent = `Unable to retrieve records for trace: ${correlationId}`;

      const p = document.createElement('p');
      p.className = 'text-muted font-mono';
      p.style.fontSize = '0.825rem';
      p.textContent = `Server response: ${errorMsg}`;

      const retryBtn = document.createElement('button');
      retryBtn.type = 'button';
      retryBtn.className = 'btn-refresh';
      retryBtn.style.marginTop = '1rem';
      retryBtn.textContent = 'Retry Selection';
      retryBtn.setAttribute('aria-label', `Retry selection for trace ${correlationId}`);
      retryBtn.setAttribute('title', `Retry selection for trace ${correlationId}`);
      retryBtn.addEventListener('click', () => this.selectTrace(correlationId));

      errCard.appendChild(errHeader);
      errCard.appendChild(h3);
      errCard.appendChild(p);
      errCard.appendChild(retryBtn);
      container.appendChild(errCard);
    },

    renderTraceDetail(trace, container) {
      container.innerHTML = '';

      // Trace Detail Top Header
      const headerBar = document.createElement('div');
      headerBar.style.display = 'flex';
      headerBar.style.justifyContent = 'space-between';
      headerBar.style.alignItems = 'center';
      headerBar.style.marginBottom = '1rem';
      headerBar.style.flexWrap = 'wrap';
      headerBar.style.gap = '0.5rem';

      const titleGroup = document.createElement('div');
      const title = document.createElement('h3');
      title.style.fontSize = '1.05rem';
      title.style.fontWeight = '700';
      title.style.margin = '0';
      title.className = 'font-mono';
      title.textContent = `Trace Correlation: ${trace.correlation_id}`;

      titleGroup.appendChild(title);

      const copyCorrBtn = document.createElement('button');
      copyCorrBtn.type = 'button';
      copyCorrBtn.className = 'copy-btn';
      copyCorrBtn.textContent = 'Copy Correlation ID';
      copyCorrBtn.setAttribute('aria-label', 'Copy Correlation ID');
      copyCorrBtn.setAttribute('title', 'Copy Correlation ID to clipboard');
      copyCorrBtn.addEventListener('click', () => this.copyToClipboard(trace.correlation_id, copyCorrBtn));

      headerBar.appendChild(titleGroup);
      headerBar.appendChild(copyCorrBtn);
      container.appendChild(headerBar);

      // Section B1: Derived Interpretation Summary
      const derivedSummaryCard = document.createElement('div');
      derivedSummaryCard.className = 'derived-summary-card mb-1';

      const summaryHeader = document.createElement('div');
      summaryHeader.className = 'derived-summary-header';

      const summaryTitle = document.createElement('span');
      summaryTitle.textContent = 'Derived Summary • Inferred Status & Evidence Correlation';

      const summaryBadge = document.createElement('span');
      summaryBadge.className = 'status-badge status-badge-not-established';
      summaryBadge.textContent = 'DERIVED INTERPRETATION';

      summaryHeader.appendChild(summaryTitle);
      summaryHeader.appendChild(summaryBadge);

      const summaryText = document.createElement('p');
      summaryText.style.fontSize = '0.85rem';
      summaryText.style.color = 'var(--text-primary)';
      summaryText.style.marginBottom = '0.5rem';

      const events = Array.isArray(trace.provenance_events) ? trace.provenance_events : [];
      const eventTypes = new Set(events.map(e => e.event_type));

      if (eventTypes.size === 0) {
        summaryText.textContent = 'Event records unestablished: No provenance events returned for this trace.';
      } else {
        const claims = [];
        if (eventTypes.has('EXECUTION_SUCCEEDED')) {
          claims.push('observed EXECUTION_SUCCEEDED event');
        }
        if (eventTypes.has('AUTHORIZATION_DENIED')) {
          claims.push('observed AUTHORIZATION_DENIED event');
        }
        if (eventTypes.has('EGRESS_BLOCKED')) {
          claims.push('observed EGRESS_BLOCKED event');
        }
        if (eventTypes.has('EXECUTION_FAILED') || eventTypes.has('EXECUTION_INTERRUPTED')) {
          claims.push('observed EXECUTION_FAILED / EXECUTION_INTERRUPTED event');
        }

        if (claims.length > 0) {
          summaryText.textContent = `Event types present in returned trace records: ${claims.join('; ')}.`;
        } else {
          summaryText.textContent = `Terminal outcome unestablished: None of the available ${events.length} event records establish execution completion, rejection, or failure.`;
        }
      }

      const disclaimerBox = document.createElement('div');
      disclaimerBox.className = 'epistemic-disclaimer-box';
      disclaimerBox.textContent = 'EPISTEMIC NOTICE: Displaying available event records establishes recorded activity, but does NOT claim a complete execution history or prove external source non-repudiation.';

      derivedSummaryCard.appendChild(summaryHeader);
      derivedSummaryCard.appendChild(summaryText);
      derivedSummaryCard.appendChild(disclaimerBox);
      container.appendChild(derivedSummaryCard);

      // Section B2: Lifecycle Overview & Authorization Records
      const metaGrid = document.createElement('div');
      metaGrid.className = 'section-grid mb-1';

      // Lifecycle Card
      const metaCard = document.createElement('div');
      metaCard.className = 'card';

      const metaHeader = document.createElement('div');
      metaHeader.className = 'card-header';
      metaHeader.textContent = 'Observed Execution Overview';
      metaCard.appendChild(metaHeader);

      const pStatus = document.createElement('p');
      pStatus.style.marginBottom = '0.4rem';
      pStatus.innerHTML = `<strong>Observed Outcome:</strong> `;
      const statusBadge = document.createElement('span');
      statusBadge.className = `badge badge-${trace.status || 'OUTCOME_UNKNOWN'}`;
      statusBadge.textContent = trace.status || 'OUTCOME_UNKNOWN';
      pStatus.appendChild(statusBadge);

      const pAction = document.createElement('p');
      pAction.style.marginBottom = '0.3rem';
      pAction.style.fontSize = '0.85rem';
      pAction.textContent = `Action Name: ${trace.action_name || 'NOT RECORDED'}`;

      const pTarget = document.createElement('p');
      pTarget.style.marginBottom = '0.3rem';
      pTarget.style.fontSize = '0.85rem';
      pTarget.textContent = `Target Resource: ${trace.target || 'NOT RECORDED'}`;

      const pReq = document.createElement('p');
      pReq.className = 'font-mono';
      pReq.style.fontSize = '0.8rem';
      pReq.style.color = 'var(--text-secondary)';
      pReq.textContent = `Request ID: ${trace.request_id || 'NOT RECORDED'}`;

      const pTimeWindow = document.createElement('p');
      pTimeWindow.className = 'font-mono';
      pTimeWindow.style.fontSize = '0.75rem';
      pTimeWindow.style.color = 'var(--text-muted)';
      pTimeWindow.style.marginTop = '0.3rem';
      pTimeWindow.textContent = `Time Span: ${trace.start_time || 'N/A'} ➔ ${trace.end_time || 'N/A'}`;

      metaCard.appendChild(pStatus);
      metaCard.appendChild(pAction);
      metaCard.appendChild(pTarget);
      metaCard.appendChild(pReq);
      metaCard.appendChild(pTimeWindow);

      // Authorization Evidence Card
      const authCard = document.createElement('div');
      authCard.className = 'card';

      const authHeader = document.createElement('div');
      authHeader.className = 'card-header';
      authHeader.textContent = 'Authorization & Policy Record';
      authCard.appendChild(authHeader);

      const ae = trace.authorization_evidence || {};
      const hasAuthEvidence = ae.authorization_token_id || ae.canonical_request_digest || ae.policy_version;

      if (!hasAuthEvidence) {
        const noAuthP = document.createElement('p');
        noAuthP.className = 'text-muted';
        noAuthP.style.fontSize = '0.825rem';
        noAuthP.textContent = 'No explicit authorization grant or token record found in provenance events for this correlation ID.';
        authCard.appendChild(noAuthP);
      } else {
        const pAuthToken = document.createElement('p');
        pAuthToken.className = 'font-mono';
        pAuthToken.style.fontSize = '0.8rem';
        pAuthToken.style.marginBottom = '0.3rem';
        pAuthToken.textContent = `Capability Token ID: ${ae.authorization_token_id || 'UNISSUED'}`;

        const pDigest = document.createElement('p');
        pDigest.className = 'font-mono';
        pDigest.style.fontSize = '0.8rem';
        pDigest.style.marginBottom = '0.3rem';
        pDigest.style.wordBreak = 'break-all';
        pDigest.textContent = `Payload Digest: ${ae.canonical_request_digest || 'UNRECORDED'}`;

        const pPolicy = document.createElement('p');
        pPolicy.style.fontSize = '0.85rem';
        pPolicy.textContent = `Policy Version: ${ae.policy_version || 'NOT RECORDED'}`;

        authCard.appendChild(pAuthToken);
        authCard.appendChild(pDigest);
        authCard.appendChild(pPolicy);
      }

      metaGrid.appendChild(metaCard);
      metaGrid.appendChild(authCard);
      container.appendChild(metaGrid);

      // Reconciliation Status Card
      const recCard = document.createElement('div');
      recCard.className = 'card mb-1';

      const recHeader = document.createElement('div');
      recHeader.className = 'card-header';
      recHeader.textContent = 'Reconciliation Status Report';
      recCard.appendChild(recHeader);

      const rec = trace.reconciliation || {};
      const recRow = document.createElement('div');
      recRow.style.display = 'flex';
      recRow.style.alignItems = 'center';
      recRow.style.gap = '0.75rem';
      recRow.style.marginBottom = '0.5rem';

      const recLabel = document.createElement('span');
      recLabel.style.fontWeight = '600';
      recLabel.style.fontSize = '0.85rem';
      recLabel.textContent = 'Reconciliation Verification: ';

      const recStatusBadge = this.createStatusBadge(rec.valid ? 'VERIFIED' : (rec.status || 'FAILED'));
      recRow.appendChild(recLabel);
      recRow.appendChild(recStatusBadge);
      recCard.appendChild(recRow);

      if (rec.violations && rec.violations.length > 0) {
        const violTitle = document.createElement('div');
        violTitle.className = 'text-danger';
        violTitle.style.fontWeight = '600';
        violTitle.style.fontSize = '0.85rem';
        violTitle.style.marginTop = '0.5rem';
        violTitle.textContent = 'Reconciliation Violations Detected:';
        recCard.appendChild(violTitle);

        const ulViol = document.createElement('ul');
        ulViol.style.marginLeft = '1.25rem';
        ulViol.style.marginTop = '0.25rem';
        rec.violations.forEach(v => {
          const li = document.createElement('li');
          li.className = 'text-danger font-mono';
          li.style.fontSize = '0.8rem';
          li.textContent = v;
          ulViol.appendChild(li);
        });
        recCard.appendChild(ulViol);
      } else {
        const noViol = document.createElement('div');
        noViol.className = 'text-muted';
        noViol.style.fontSize = '0.8rem';
        noViol.textContent = 'Zero reconciliation violations detected across provenance chain.';
        recCard.appendChild(noViol);
      }
      container.appendChild(recCard);

      // Area C & B: Observed Event Timeline & Dedicated Evidence Inspector
      const eventsCard = document.createElement('div');
      eventsCard.className = 'card';

      const eventsHeader = document.createElement('div');
      eventsHeader.className = 'card-header';
      eventsHeader.textContent = 'Observed Chronological Event Timeline';
      eventsCard.appendChild(eventsHeader);

      if (events.length === 0) {
        const noEv = document.createElement('p');
        noEv.className = 'text-muted text-center';
        noEv.style.padding = '1rem';
        noEv.textContent = 'No recorded provenance events exist for this execution trace correlation ID.';
        eventsCard.appendChild(noEv);
      } else {
        // Check for ambiguous or missing timestamps
        let hasMissingOrAmbiguousTimestamps = false;
        events.forEach(e => {
          if (!e.timestamp || e.timestamp === 'UNKNOWN' || e.timestamp === 'N/A') {
            hasMissingOrAmbiguousTimestamps = true;
          }
        });

        if (hasMissingOrAmbiguousTimestamps) {
          const ambigNotice = document.createElement('div');
          ambigNotice.className = 'epistemic-disclaimer-box mb-1';
          ambigNotice.style.borderColor = 'var(--status-halted-fg)';
          ambigNotice.textContent = 'NOTICE: One or more recorded events lack a reliable timestamp. Displayed sequence ordering reflects append-only sequence numbers rather than strictly verified physical real-world time.';
          eventsCard.appendChild(ambigNotice);
        }

        const tableResp = document.createElement('div');
        tableResp.className = 'table-responsive';

        const table = document.createElement('table');
        table.className = 'data-table';
        table.setAttribute('aria-label', 'Recorded Events for Selected Trace');

        const thead = document.createElement('thead');
        thead.innerHTML = `
          <tr>
            <th>Seq #</th>
            <th>Timestamp</th>
            <th>Event Type</th>
            <th>Source</th>
            <th>Entry Hash</th>
          </tr>
        `;
        table.appendChild(thead);

        const tbody = document.createElement('tbody');

        events.forEach(ev => {
          const isSelectedEvent = (this.state.selectedEventSeq === ev.sequence_number) ||
            (!this.state.selectedEventSeq && ev.sequence_number === events[0].sequence_number);

          const tr = document.createElement('tr');
          tr.className = `clickable ${isSelectedEvent ? 'selected' : ''}`;
          tr.setAttribute('role', 'button');
          tr.setAttribute('tabindex', '0');
          tr.setAttribute('aria-selected', isSelectedEvent ? 'true' : 'false');
          tr.setAttribute('aria-label', `Inspect event sequence ${ev.sequence_number}, type ${ev.event_type}`);

          tr.addEventListener('click', () => {
            this.state.selectedEventSeq = ev.sequence_number;
            this.renderTraceDetail(trace, container);
          });
          tr.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              this.state.selectedEventSeq = ev.sequence_number;
              this.renderTraceDetail(trace, container);
            }
          });

          const tdSeq = document.createElement('td');
          tdSeq.className = 'font-mono';
          tdSeq.textContent = ev.sequence_number ?? '-';

          const tdTs = document.createElement('td');
          tdTs.className = 'font-mono';
          tdTs.style.fontSize = '0.75rem';
          tdTs.textContent = ev.timestamp || 'TIMESTAMP UNRECORDED';

          const tdType = document.createElement('td');
          tdType.style.fontWeight = '600';
          tdType.textContent = ev.event_type || 'UNKNOWN';

          const tdSource = document.createElement('td');
          tdSource.textContent = ev.provenance_source || 'UNKNOWN';

          const tdHash = document.createElement('td');
          tdHash.className = 'font-mono';
          tdHash.style.fontSize = '0.75rem';
          const fullHash = ev.entry_hash || '';
          tdHash.textContent = fullHash ? (fullHash.length > 18 ? fullHash.substring(0, 16) + '...' : fullHash) : 'N/A';
          tdHash.title = fullHash;

          tr.appendChild(tdSeq);
          tr.appendChild(tdTs);
          tr.appendChild(tdType);
          tr.appendChild(tdSource);
          tr.appendChild(tdHash);
          tbody.appendChild(tr);
        });

        table.appendChild(tbody);
        tableResp.appendChild(table);
        eventsCard.appendChild(tableResp);

        // Area C: Evidence Inspector Panel for Selected Event
        const selectedEv = events.find(e => e.sequence_number === this.state.selectedEventSeq) || events[0];
        if (selectedEv) {
          const inspectorBox = document.createElement('div');
          inspectorBox.id = 'area-evidence-inspector';
          inspectorBox.style.marginTop = '1.25rem';
          inspectorBox.style.borderTop = '1px solid var(--border-default)';
          inspectorBox.style.paddingTop = '1rem';

          const inspHeader = document.createElement('div');
          inspHeader.style.display = 'flex';
          inspHeader.style.justifyContent = 'space-between';
          inspHeader.style.alignItems = 'center';
          inspHeader.style.marginBottom = '0.75rem';
          inspHeader.style.flexWrap = 'wrap';
          inspHeader.style.gap = '0.5rem';

          const inspTitle = document.createElement('h4');
          inspTitle.style.fontSize = '0.9rem';
          inspTitle.style.fontWeight = '700';
          inspTitle.style.color = 'var(--accent-primary)';
          inspTitle.textContent = `Evidence Inspector: Event #${selectedEv.sequence_number} (${selectedEv.event_type})`;

          const inspCopyBtn = document.createElement('button');
          inspCopyBtn.type = 'button';
          inspCopyBtn.className = 'copy-btn';
          inspCopyBtn.textContent = 'Copy Event Payload JSON';
          inspCopyBtn.setAttribute('aria-label', `Copy full JSON payload for event sequence ${selectedEv.sequence_number}`);
          inspCopyBtn.setAttribute('title', `Copy JSON payload for event sequence ${selectedEv.sequence_number}`);
          inspCopyBtn.addEventListener('click', () => {
            this.copyToClipboard(JSON.stringify(selectedEv, null, 2), inspCopyBtn);
          });

          inspHeader.appendChild(inspTitle);
          inspHeader.appendChild(inspCopyBtn);
          inspectorBox.appendChild(inspHeader);

          // Grid Layout for Key Fields & Full Raw JSON Payload
          const inspectorGrid = document.createElement('div');
          inspectorGrid.className = 'evidence-inspector-grid';

          // Field Inspector Breakdown Card
          const fieldsCard = document.createElement('div');
          fieldsCard.className = 'card';
          fieldsCard.style.padding = '0.85rem';

          const fieldsHeader = document.createElement('div');
          fieldsHeader.className = 'card-header';
          fieldsHeader.textContent = 'Structured Event Metadata';
          fieldsCard.appendChild(fieldsHeader);

          const fieldList = [
            { label: 'Event ID', value: selectedEv.event_id, mono: true },
            { label: 'Event Type', value: selectedEv.event_type, bold: true },
            { label: 'Provenance Source', value: selectedEv.provenance_source },
            { label: 'Sequence Number', value: selectedEv.sequence_number, mono: true },
            { label: 'Timestamp', value: selectedEv.timestamp, mono: true },
            { label: 'Correlation ID', value: selectedEv.correlation_id, mono: true, copyable: true },
            { label: 'Request ID', value: selectedEv.request_id, mono: true, copyable: true },
            { label: 'Action Name', value: selectedEv.action_name },
            { label: 'Target Resource', value: selectedEv.target },
            { label: 'Capability Token ID', value: selectedEv.authorization_token_id, mono: true, copyable: true },
            { label: 'Canonical Request Digest', value: selectedEv.canonical_request_digest, mono: true, copyable: true },
            { label: 'Policy Version', value: selectedEv.policy_version, mono: true },
            { label: 'Previous Entry Hash', value: selectedEv.prev_hash, mono: true, copyable: true },
            { label: 'Entry Cryptographic Hash', value: selectedEv.entry_hash, mono: true, copyable: true }
          ];

          fieldList.forEach(item => {
            const row = document.createElement('div');
            row.style.marginBottom = '0.4rem';
            row.style.fontSize = '0.8rem';
            row.style.wordBreak = 'break-all';

            const lbl = document.createElement('span');
            lbl.style.color = 'var(--text-secondary)';
            lbl.style.fontWeight = '600';
            lbl.textContent = `${item.label}: `;
            row.appendChild(lbl);

            const valSpan = document.createElement('span');
            if (item.value !== null && item.value !== undefined && item.value !== '') {
              valSpan.textContent = String(item.value);
              if (item.mono) valSpan.className = 'font-mono';
              if (item.bold) valSpan.style.fontWeight = '700';
              row.appendChild(valSpan);

              if (item.copyable) {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'copy-btn';
                btn.style.marginLeft = '0.4rem';
                btn.style.padding = '0.1rem 0.35rem';
                btn.style.fontSize = '0.65rem';
                btn.textContent = 'Copy';
                btn.setAttribute('aria-label', `Copy ${item.label}`);
                btn.setAttribute('title', `Copy ${item.label} to clipboard`);
                btn.addEventListener('click', () => this.copyToClipboard(String(item.value), btn));
                row.appendChild(btn);
              }
            } else {
              valSpan.className = 'text-dim';
              valSpan.textContent = 'UNAVAILABLE / NOT RECORDED';
              row.appendChild(valSpan);
            }

            fieldsCard.appendChild(row);
          });

          // Raw JSON Block Card
          const jsonCard = document.createElement('div');
          jsonCard.className = 'card';
          jsonCard.style.padding = '0.85rem';

          const jsonHeader = document.createElement('div');
          jsonHeader.className = 'card-header';
          jsonHeader.textContent = 'Raw Event JSON Record';
          jsonCard.appendChild(jsonHeader);

          const pre = document.createElement('pre');
          pre.className = 'inspector-block';
          pre.textContent = JSON.stringify(selectedEv, null, 2);
          jsonCard.appendChild(pre);

          inspectorGrid.appendChild(fieldsCard);
          inspectorGrid.appendChild(jsonCard);
          inspectorBox.appendChild(inspectorGrid);
          eventsCard.appendChild(inspectorBox);
        }
      }

      container.appendChild(eventsCard);
    },

    // -------------------------------------------------------------------------
    // View 3: Provenance Explorer
    // -------------------------------------------------------------------------
    async loadProvenance() {
      const recListUl = document.getElementById('provenance-record-list');
      if (recListUl && (!this.state.provenanceData || !this.state.provenanceData.events)) {
        recListUl.innerHTML = '<li class="text-muted text-center" style="padding: 1.5rem;">Loading provenance records...</li>';
      }

      try {
        const [provRes, tracesRes] = await Promise.all([
          fetch('/api/provenance'),
          fetch('/api/traces').catch(() => null)
        ]);

        if (!provRes.ok) throw new Error(`HTTP error ${provRes.status}`);
        const provData = await provRes.json();
        this.state.provenanceData = provData;

        if (tracesRes && tracesRes.ok) {
          this.state.tracesData = await tracesRes.json();
        }

        this.renderProvenance();
      } catch (err) {
        console.error('Failed to load provenance data:', err);
        this.renderProvenanceError(err.message);
      }
    },

    renderProvenanceError(errorMsg) {
      const recListUl = document.getElementById('provenance-record-list');
      if (recListUl) {
        recListUl.innerHTML = '';
        const errLi = document.createElement('li');
        errLi.className = 'text-danger text-center';
        errLi.style.padding = '1.5rem 1rem';

        const msgSpan = document.createElement('span');
        msgSpan.style.display = 'block';
        msgSpan.style.marginBottom = '0.5rem';
        msgSpan.style.fontWeight = '600';
        msgSpan.textContent = 'Failed to load provenance data.';

        const detailSpan = document.createElement('span');
        detailSpan.className = 'text-muted font-mono';
        detailSpan.style.fontSize = '0.75rem';
        detailSpan.style.display = 'block';
        detailSpan.style.marginBottom = '0.75rem';
        detailSpan.textContent = `Server API Error: ${errorMsg}`;

        const retryBtn = document.createElement('button');
        retryBtn.type = 'button';
        retryBtn.className = 'btn-refresh';
        retryBtn.textContent = 'Retry Loading Provenance';
        retryBtn.setAttribute('aria-label', 'Retry loading provenance records');
        retryBtn.setAttribute('title', 'Retry loading provenance records');
        retryBtn.addEventListener('click', () => this.loadProvenance());

        errLi.appendChild(msgSpan);
        errLi.appendChild(detailSpan);
        errLi.appendChild(retryBtn);
        recListUl.appendChild(errLi);
      }

      const countBadge = document.getElementById('provenance-count');
      if (countBadge) countBadge.textContent = 'ERROR';
    },

    renderProvenance() {
      const data = this.state.provenanceData;
      if (!data) return;

      this.renderProvenanceSummaryPanels(data.summary_panels || {});
      this.renderProvenanceFindings(data.findings || []);
      this.renderProvenanceRecordList();
    },

    renderProvenanceSummaryPanels(panels) {
      // Panel 1: Availability
      const pAvail = panels.availability || {};
      const elAvailBadge = document.getElementById('summary-avail-badge');
      const elAvailMsg = document.getElementById('summary-avail-msg');
      if (elAvailBadge) {
        const badge = this.createStatusBadge(pAvail.status || 'UNAVAILABLE');
        elAvailBadge.replaceWith(badge);
        badge.id = 'summary-avail-badge';
      }
      if (elAvailMsg) {
        elAvailMsg.textContent = pAvail.message || 'Availability unverified.';
      }

      // Panel 2: Integrity
      const pInteg = panels.integrity || {};
      const elIntegBadge = document.getElementById('summary-integrity-badge');
      const elIntegMsg = document.getElementById('summary-integrity-msg');
      if (elIntegBadge) {
        const badge = this.createStatusBadge(pInteg.status || 'UNAVAILABLE');
        elIntegBadge.replaceWith(badge);
        badge.id = 'summary-integrity-badge';
      }
      if (elIntegMsg) {
        let msg = pInteg.message || 'Integrity unverified.';
        if (pInteg.last_hash) {
          const shortHash = pInteg.last_hash.substring(0, 16) + '...';
          msg += ` (Tail Hash: ${shortHash})`;
        }
        elIntegMsg.textContent = msg;
      }

      // Panel 3: Coverage
      const pCov = panels.coverage || {};
      const elCovBadge = document.getElementById('summary-coverage-badge');
      const elCovMsg = document.getElementById('summary-coverage-msg');
      if (elCovBadge) {
        const badge = this.createStatusBadge(pCov.status || 'UNVERIFIED');
        elCovBadge.replaceWith(badge);
        badge.id = 'summary-coverage-badge';
      }
      if (elCovMsg) {
        elCovMsg.textContent = pCov.message || 'Trace coverage unverified.';
      }

      // Panel 4: Authenticity
      const pAuth = panels.authenticity || {};
      const elAuthBadge = document.getElementById('summary-authenticity-badge');
      const elAuthMsg = document.getElementById('summary-authenticity-msg');
      if (elAuthBadge) {
        const badge = this.createStatusBadge(pAuth.status || 'NOT ESTABLISHED');
        elAuthBadge.replaceWith(badge);
        badge.id = 'summary-authenticity-badge';
      }
      if (elAuthMsg) {
        elAuthMsg.textContent = pAuth.message || 'Source authenticity unestablished.';
      }
    },

    renderProvenanceFindings(findings) {
      const container = document.getElementById('provenance-findings-container');
      if (!container) return;
      container.innerHTML = '';

      if (!findings || findings.length === 0) {
        const p = document.createElement('p');
        p.className = 'text-muted text-center';
        p.style.padding = '0.5rem';
        p.textContent = 'Zero verification findings or anomalies reported.';
        container.appendChild(p);
        return;
      }

      const grid = document.createElement('div');
      grid.style.display = 'grid';
      grid.style.gridTemplateColumns = 'repeat(auto-fit, minmax(280px, 1fr))';
      grid.style.gap = '0.75rem';

      findings.forEach(f => {
        const card = document.createElement('div');
        card.className = 'status-block';
        card.style.fontSize = '0.825rem';

        if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
          card.style.borderColor = 'var(--status-failed-border)';
          card.style.backgroundColor = 'var(--status-failed-bg)';
        } else if (f.severity === 'WARNING') {
          card.style.borderColor = 'var(--status-halted-border)';
          card.style.backgroundColor = 'var(--status-halted-bg)';
        } else {
          card.style.borderColor = 'var(--border-default)';
        }

        const titleRow = document.createElement('div');
        titleRow.style.display = 'flex';
        titleRow.style.justifyContent = 'space-between';
        titleRow.style.alignItems = 'center';
        titleRow.style.marginBottom = '0.35rem';

        const titleSpan = document.createElement('strong');
        titleSpan.textContent = f.title || f.code;

        const sevBadge = document.createElement('span');
        sevBadge.className = 'font-mono text-dim';
        sevBadge.style.fontSize = '0.7rem';
        sevBadge.style.padding = '0.1rem 0.35rem';
        sevBadge.style.borderRadius = '3px';
        sevBadge.style.border = '1px solid var(--border-default)';
        sevBadge.textContent = f.severity || 'INFO';

        titleRow.appendChild(titleSpan);
        titleRow.appendChild(sevBadge);

        const descP = document.createElement('div');
        descP.className = 'text-muted';
        descP.style.fontSize = '0.8rem';
        descP.textContent = f.description;

        card.appendChild(titleRow);
        card.appendChild(descP);
        grid.appendChild(card);
      });

      container.appendChild(grid);
    },

    renderProvenanceRecordList() {
      const listUl = document.getElementById('provenance-record-list');
      if (!listUl) return;
      listUl.innerHTML = '';

      const data = this.state.provenanceData;
      const events = (data && Array.isArray(data.events)) ? data.events : [];

      let filtered = events.filter(ev => {
        if (this.state.provenanceFilterType !== 'ALL' && ev.event_type !== this.state.provenanceFilterType) {
          return false;
        }
        if (this.state.provenanceSearchQuery) {
          const q = this.state.provenanceSearchQuery;
          const id = (ev.event_id || '').toLowerCase();
          const corr = (ev.correlation_id || '').toLowerCase();
          const req = (ev.request_id || '').toLowerCase();
          const src = (ev.provenance_source || '').toLowerCase();
          const act = (ev.action_name || '').toLowerCase();
          const tgt = (ev.target || '').toLowerCase();
          const hash = (ev.entry_hash || '').toLowerCase();
          const prev = (ev.prev_hash || '').toLowerCase();
          return id.includes(q) || corr.includes(q) || req.includes(q) || src.includes(q) || act.includes(q) || tgt.includes(q) || hash.includes(q) || prev.includes(q);
        }
        return true;
      });

      const countBadge = document.getElementById('provenance-count');
      if (countBadge) {
        const total = events.length;
        const visible = filtered.length;
        countBadge.textContent = total === visible ? `${total}` : `${visible} of ${total}`;
        countBadge.setAttribute('aria-label', total === visible ? `${total} records` : `${visible} of ${total} records shown`);
      }

      if (filtered.length === 0) {
        const emptyLi = document.createElement('li');
        emptyLi.className = 'text-muted text-center';
        emptyLi.style.padding = '1.5rem 1rem';

        const hasFilters = this.state.provenanceSearchQuery || this.state.provenanceFilterType !== 'ALL';
        if (hasFilters) {
          const msgSpan = document.createElement('span');
          msgSpan.style.display = 'block';
          msgSpan.style.marginBottom = '0.5rem';
          msgSpan.textContent = 'No provenance records match active search query or filter.';

          const clearBtn = document.createElement('button');
          clearBtn.type = 'button';
          clearBtn.className = 'btn-refresh';
          clearBtn.textContent = 'Clear Filters';
          clearBtn.setAttribute('aria-label', 'Clear search query and event type filter');
          clearBtn.setAttribute('title', 'Clear active search query and event type filter');
          clearBtn.addEventListener('click', () => {
            this.state.provenanceSearchQuery = '';
            this.state.provenanceFilterType = 'ALL';
            const searchInput = document.getElementById('provenance-search');
            if (searchInput) {
              searchInput.value = '';
              searchInput.focus();
            }
            const typeFilter = document.getElementById('provenance-type-filter');
            if (typeFilter) typeFilter.value = 'ALL';
            this.renderProvenanceRecordList();
          });

          emptyLi.appendChild(msgSpan);
          emptyLi.appendChild(clearBtn);
        } else {
          emptyLi.textContent = 'No provenance records present in log stream.';
        }

        listUl.appendChild(emptyLi);
        return;
      }

      filtered.forEach((ev, index) => {
        const recId = ev.event_id || `seq_${ev.sequence_number}`;
        const isSelected = this.state.selectedRecordId === recId;

        const li = document.createElement('li');
        li.className = `trace-item ${isSelected ? 'active' : ''}`;
        li.setAttribute('role', 'option');
        li.setAttribute('tabindex', '0');
        li.setAttribute('aria-selected', isSelected ? 'true' : 'false');
        li.setAttribute('aria-label', `Provenance event sequence ${ev.sequence_number}, type ${ev.event_type}`);

        li.addEventListener('click', () => this.selectProvenanceRecord(recId));
        li.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            this.selectProvenanceRecord(recId);
          } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            const items = listUl.querySelectorAll('.trace-item');
            if (index + 1 < items.length) items[index + 1].focus();
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            const items = listUl.querySelectorAll('.trace-item');
            if (index - 1 >= 0) items[index - 1].focus();
          } else if (e.key === 'Home') {
            e.preventDefault();
            const items = listUl.querySelectorAll('.trace-item');
            if (items.length > 0) items[0].focus();
          } else if (e.key === 'End') {
            e.preventDefault();
            const items = listUl.querySelectorAll('.trace-item');
            if (items.length > 0) items[items.length - 1].focus();
          }
        });

        const headerDiv = document.createElement('div');
        headerDiv.className = 'trace-item-header';

        const seqSpan = document.createElement('span');
        seqSpan.className = 'font-mono';
        seqSpan.style.fontWeight = '700';
        seqSpan.style.fontSize = '0.8rem';
        seqSpan.style.color = 'var(--accent-primary)';
        seqSpan.textContent = `#${ev.sequence_number ?? '-'}`;

        const typeSpan = document.createElement('span');
        typeSpan.className = 'trace-id';
        typeSpan.style.fontSize = '0.8rem';
        typeSpan.textContent = ev.event_type || 'UNKNOWN';

        headerDiv.appendChild(seqSpan);
        headerDiv.appendChild(typeSpan);

        const subDiv = document.createElement('div');
        subDiv.className = 'text-muted';
        subDiv.style.fontSize = '0.75rem';
        subDiv.style.marginTop = '0.2rem';
        subDiv.textContent = `Src: ${ev.provenance_source || 'N/A'} • ${ev.action_name || 'N/A'}`;

        const hashDiv = document.createElement('div');
        hashDiv.className = 'font-mono text-dim';
        hashDiv.style.fontSize = '0.7rem';
        hashDiv.style.marginTop = '0.15rem';
        const entryHashShort = (ev.entry_hash || 'N/A').substring(0, 16) + '...';
        hashDiv.textContent = `Hash: ${entryHashShort}`;

        li.appendChild(headerDiv);
        li.appendChild(subDiv);
        li.appendChild(hashDiv);
        listUl.appendChild(li);
      });
    },

    selectProvenanceRecord(recId) {
      this.state.selectedRecordId = recId;
      this.renderProvenanceRecordList();

      const emptyDiv = document.getElementById('provenance-inspector-empty');
      const contentDiv = document.getElementById('provenance-inspector-content');

      if (!recId) {
        if (emptyDiv) emptyDiv.classList.remove('hidden');
        if (contentDiv) contentDiv.classList.add('hidden');
        return;
      }

      const events = (this.state.provenanceData && Array.isArray(this.state.provenanceData.events)) ? this.state.provenanceData.events : [];
      const record = events.find(e => (e.event_id === recId) || (`seq_${e.sequence_number}` === recId));

      if (!record) {
        if (emptyDiv) emptyDiv.classList.remove('hidden');
        if (contentDiv) contentDiv.classList.add('hidden');
        return;
      }

      if (emptyDiv) emptyDiv.classList.add('hidden');
      if (contentDiv) {
        contentDiv.classList.remove('hidden');
        this.renderProvenanceRecordInspector(record, contentDiv);
      }
    },

    renderProvenanceRecordInspector(record, container) {
      container.innerHTML = '';

      // Header with Copy and Related Trace Jump
      const headerBar = document.createElement('div');
      headerBar.style.display = 'flex';
      headerBar.style.justifyContent = 'space-between';
      headerBar.style.alignItems = 'center';
      headerBar.style.marginBottom = '1rem';
      headerBar.style.flexWrap = 'wrap';
      headerBar.style.gap = '0.5rem';

      const titleGroup = document.createElement('div');
      const title = document.createElement('h3');
      title.style.fontSize = '1.05rem';
      title.style.fontWeight = '700';
      title.style.margin = '0';
      title.className = 'font-mono';
      title.textContent = `Record #${record.sequence_number} • ${record.event_type}`;
      titleGroup.appendChild(title);

      const actionBtnGroup = document.createElement('div');
      actionBtnGroup.style.display = 'flex';
      actionBtnGroup.style.gap = '0.5rem';

      // Related Trace Button
      const corrId = record.correlation_id;
      const matchingTrace = corrId ? this.state.tracesData.find(t => t.correlation_id === corrId) : null;

      if (matchingTrace) {
        const traceBtn = document.createElement('button');
        traceBtn.type = 'button';
        traceBtn.className = 'quick-entry-btn';
        traceBtn.style.padding = '0.25rem 0.6rem';
        traceBtn.style.fontSize = '0.75rem';
        traceBtn.setAttribute('aria-label', `Navigate to related execution trace ${corrId}`);
        traceBtn.setAttribute('title', `Navigate to related execution trace ${corrId}`);
        traceBtn.innerHTML = `<span>View Related Trace</span> <span class="arrow" aria-hidden="true">➔</span>`;
        traceBtn.addEventListener('click', () => {
          this.state.selectedTraceId = corrId;
          this.switchTab('traces');
          this.selectTrace(corrId);
        });
        actionBtnGroup.appendChild(traceBtn);
      }

      const copyRecordBtn = document.createElement('button');
      copyRecordBtn.type = 'button';
      copyRecordBtn.className = 'copy-btn';
      copyRecordBtn.textContent = 'Copy Record JSON';
      copyRecordBtn.setAttribute('aria-label', `Copy JSON payload for record sequence ${record.sequence_number}`);
      copyRecordBtn.setAttribute('title', `Copy JSON payload for record sequence ${record.sequence_number}`);
      copyRecordBtn.addEventListener('click', () => this.copyToClipboard(JSON.stringify(record, null, 2), copyRecordBtn));
      actionBtnGroup.appendChild(copyRecordBtn);

      headerBar.appendChild(titleGroup);
      headerBar.appendChild(actionBtnGroup);
      container.appendChild(headerBar);

      // Card 1: Key Metadata Breakdown
      const metaCard = document.createElement('div');
      metaCard.className = 'card mb-1';

      const metaHeader = document.createElement('div');
      metaHeader.className = 'card-header';
      metaHeader.textContent = 'Record Information & Context';
      metaCard.appendChild(metaHeader);

      const fieldList = [
        { label: 'Record Identifier', value: record.event_id, mono: true, copyable: true },
        { label: 'Event Type', value: record.event_type, bold: true },
        { label: 'Provenance Source', value: record.provenance_source },
        { label: 'Sequence Number', value: record.sequence_number, mono: true },
        { label: 'Timestamp', value: record.timestamp || 'TIMESTAMP UNRECORDED', mono: true },
        { label: 'Correlation ID', value: record.correlation_id, mono: true, copyable: true },
        { label: 'Request ID', value: record.request_id, mono: true, copyable: true },
        { label: 'Action Name', value: record.action_name },
        { label: 'Target Resource', value: record.target },
        { label: 'Capability Token ID', value: record.authorization_token_id, mono: true, copyable: true },
        { label: 'Canonical Request Digest', value: record.canonical_request_digest, mono: true, copyable: true },
        { label: 'Policy Version', value: record.policy_version, mono: true }
      ];

      fieldList.forEach(item => {
        const row = document.createElement('div');
        row.style.marginBottom = '0.4rem';
        row.style.fontSize = '0.8rem';
        row.style.wordBreak = 'break-all';

        const lbl = document.createElement('span');
        lbl.style.color = 'var(--text-secondary)';
        lbl.style.fontWeight = '600';
        lbl.textContent = `${item.label}: `;
        row.appendChild(lbl);

        const valSpan = document.createElement('span');
        if (item.value !== null && item.value !== undefined && item.value !== '') {
          valSpan.textContent = String(item.value);
          if (item.mono) valSpan.className = 'font-mono';
          if (item.bold) valSpan.style.fontWeight = '700';
          row.appendChild(valSpan);

          if (item.copyable) {
            const btn = document.createElement('button');
              btn.type = 'button';
            btn.className = 'copy-btn';
            btn.style.marginLeft = '0.4rem';
            btn.style.padding = '0.1rem 0.35rem';
            btn.style.fontSize = '0.65rem';
            btn.textContent = 'Copy';
            btn.setAttribute('aria-label', `Copy ${item.label}`);
              btn.setAttribute('title', `Copy ${item.label} to clipboard`);
            btn.addEventListener('click', () => this.copyToClipboard(String(item.value), btn));
            row.appendChild(btn);
          }
        } else {
          valSpan.className = 'text-dim';
          valSpan.textContent = 'UNAVAILABLE / NOT RECORDED';
          row.appendChild(valSpan);
        }

        metaCard.appendChild(row);
      });

      container.appendChild(metaCard);

      // Card 2: Cryptographic Chain Linkage Inspector
      const chainCard = document.createElement('div');
      chainCard.className = 'card mb-1';

      const chainHeader = document.createElement('div');
      chainHeader.className = 'card-header';
      chainHeader.textContent = 'Cryptographic Sequence Chaining Linkage';
      chainCard.appendChild(chainHeader);

      const prevRow = document.createElement('div');
      prevRow.style.marginBottom = '0.5rem';
      prevRow.style.fontSize = '0.8rem';
      prevRow.style.wordBreak = 'break-all';

      const prevLbl = document.createElement('strong');
      prevLbl.textContent = 'Predecessor Entry Hash (prev_hash): ';

      const prevVal = document.createElement('span');
      prevVal.className = 'font-mono text-dim';
      prevVal.textContent = record.prev_hash || 'GENESIS (No Predecessor)';

      prevRow.appendChild(prevLbl);
      prevRow.appendChild(prevVal);

      if (record.prev_hash) {
        const copyPrevBtn = document.createElement('button');
        copyPrevBtn.type = 'button';
        copyPrevBtn.className = 'copy-btn';
        copyPrevBtn.style.marginLeft = '0.4rem';
        copyPrevBtn.style.padding = '0.1rem 0.35rem';
        copyPrevBtn.style.fontSize = '0.65rem';
        copyPrevBtn.textContent = 'Copy';
        copyPrevBtn.setAttribute('aria-label', 'Copy predecessor entry hash');
        copyPrevBtn.setAttribute('title', 'Copy predecessor entry hash to clipboard');
        copyPrevBtn.addEventListener('click', () => this.copyToClipboard(record.prev_hash, copyPrevBtn));
        prevRow.appendChild(copyPrevBtn);
      }

      const currRow = document.createElement('div');
      currRow.style.marginBottom = '0.5rem';
      currRow.style.fontSize = '0.8rem';
      currRow.style.wordBreak = 'break-all';

      const currLbl = document.createElement('strong');
      currLbl.textContent = 'Current Cryptographic Entry Hash (entry_hash): ';

      const currVal = document.createElement('span');
      currVal.className = 'font-mono';
      currVal.style.color = 'var(--accent-primary)';
      currVal.textContent = record.entry_hash || 'UNAVAILABLE';

      currRow.appendChild(currLbl);
      currRow.appendChild(currVal);

      if (record.entry_hash) {
        const copyCurrBtn = document.createElement('button');
        copyCurrBtn.type = 'button';
        copyCurrBtn.className = 'copy-btn';
        copyCurrBtn.style.marginLeft = '0.4rem';
        copyCurrBtn.style.padding = '0.1rem 0.35rem';
        copyCurrBtn.style.fontSize = '0.65rem';
        copyCurrBtn.textContent = 'Copy';
        copyCurrBtn.setAttribute('aria-label', 'Copy current entry hash');
        copyCurrBtn.setAttribute('title', 'Copy current entry hash to clipboard');
        copyCurrBtn.addEventListener('click', () => this.copyToClipboard(record.entry_hash, copyCurrBtn));
        currRow.appendChild(copyCurrBtn);
      }

      chainCard.appendChild(prevRow);
      chainCard.appendChild(currRow);
      container.appendChild(chainCard);

      // Card 3: Raw JSON Record Payload
      const jsonCard = document.createElement('div');
      jsonCard.className = 'card';

      const jsonHeader = document.createElement('div');
      jsonHeader.className = 'card-header';
      jsonHeader.textContent = 'Original Raw Record JSON Payload';
      jsonCard.appendChild(jsonHeader);

      const pre = document.createElement('pre');
      pre.className = 'inspector-block';
      pre.textContent = JSON.stringify(record, null, 2);

      jsonCard.appendChild(pre);
      container.appendChild(jsonCard);
    },

    // -------------------------------------------------------------------------
    // View 4: Benchmark Workbench
    // -------------------------------------------------------------------------
    async loadBenchmarks() {
      const caseListUl = document.getElementById('benchmark-case-list');
      if (caseListUl && (!this.state.benchmarkData)) {
        caseListUl.innerHTML = '<li class="text-muted text-center" style="padding: 1.5rem;">Loading benchmark cases...</li>';
      }

      try {
        const res = await fetch('/api/benchmarks');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        this.state.benchmarkData = data;
        this.populateBaselineFilterOptions();
        this.renderBenchmarks();
      } catch (err) {
        console.error('Failed to load benchmarks:', err);
        this.renderBenchmarkLoadError(err.message);
      }
    },

    renderBenchmarkLoadError(errorMsg) {
      const statusBadge = document.getElementById('benchmark-artifacts-status');
      if (statusBadge) {
        const badge = this.createStatusBadge('UNAVAILABLE');
        statusBadge.replaceWith(badge);
        badge.id = 'benchmark-artifacts-status';
      }

      const caseListUl = document.getElementById('benchmark-case-list');
      if (caseListUl) {
        caseListUl.innerHTML = '';
        const errLi = document.createElement('li');
        errLi.className = 'text-danger text-center';
        errLi.style.padding = '1.5rem 1rem';

        const msgSpan = document.createElement('span');
        msgSpan.style.display = 'block';
        msgSpan.style.marginBottom = '0.5rem';
        msgSpan.style.fontWeight = '600';
        msgSpan.textContent = 'Failed to load benchmark artifacts.';

        const detailSpan = document.createElement('span');
        detailSpan.className = 'text-muted font-mono';
        detailSpan.style.fontSize = '0.75rem';
        detailSpan.style.display = 'block';
        detailSpan.style.marginBottom = '0.75rem';
        detailSpan.textContent = `Server API Error: ${errorMsg}`;

        const retryBtn = document.createElement('button');
        retryBtn.type = 'button';
        retryBtn.className = 'btn-refresh';
        retryBtn.textContent = 'Retry Loading Benchmarks';
        retryBtn.setAttribute('aria-label', 'Retry loading benchmark artifacts');
        retryBtn.setAttribute('title', 'Retry loading benchmark artifacts');
        retryBtn.addEventListener('click', () => this.loadBenchmarks());

        errLi.appendChild(msgSpan);
        errLi.appendChild(detailSpan);
        errLi.appendChild(retryBtn);
        caseListUl.appendChild(errLi);
      }

      const countBadge = document.getElementById('benchmark-case-count');
      if (countBadge) countBadge.textContent = 'ERROR';
    },

    populateBaselineFilterOptions() {
      const selectEl = document.getElementById('benchmark-case-baseline-filter');
      if (!selectEl) return;

      const data = this.state.benchmarkData;
      const pc = data?.per_case_results;
      const caseList = (pc?.available && Array.isArray(pc.data)) ? pc.data : [];

      const distinctBaselines = new Set();
      caseList.forEach(c => {
        if (c && c.baseline) distinctBaselines.add(c.baseline);
      });

      // Preserve existing selected value if possible
      const currentVal = selectEl.value || 'ALL';

      selectEl.innerHTML = '';
      const allOpt = document.createElement('option');
      allOpt.value = 'ALL';
      allOpt.textContent = 'All Baselines';
      selectEl.appendChild(allOpt);

      Array.from(distinctBaselines).sort().forEach(baseName => {
        const opt = document.createElement('option');
        opt.value = baseName;
        opt.textContent = baseName;
        selectEl.appendChild(opt);
      });

      selectEl.value = Array.from(distinctBaselines).includes(currentVal) ? currentVal : 'ALL';
      this.state.caseBaselineFilter = selectEl.value;
    },

    renderBenchmarks() {
      const data = this.state.benchmarkData;
      if (!data) return;

      this.renderRunSummary();
      this.renderConditionComparisons();
      this.renderBenchmarkCasesList();
      this.renderMethodologyAndLimitations();
    },

    // -------------------------------------------------------------------------
    // Workbench Section 1: Run Summary
    // -------------------------------------------------------------------------
    renderRunSummary() {
      const data = this.state.benchmarkData || {};
      const abl = data.ablation_table || {};
      const pc = data.per_case_results || {};

      const ablData = abl.available ? abl.data : null;
      const pcData = (pc.available && Array.isArray(pc.data)) ? pc.data : null;

      // Artifact Status Badge
      const statusBadge = document.getElementById('benchmark-artifacts-status');
      if (statusBadge) {
        let statusStr = 'UNAVAILABLE';
        if (abl.available && pc.available) statusStr = 'VERIFIED';
        else if (abl.available || pc.available) statusStr = 'PARTIAL';
        const badge = this.createStatusBadge(statusStr);
        statusBadge.replaceWith(badge);
        badge.id = 'benchmark-artifacts-status';
      }

      // Run Identifier
      const runId = (ablData && ablData.run_id) ? ablData.run_id : ((pcData && pcData.length > 0 && pcData[0].run_id) ? pcData[0].run_id : null);
      this.renderSummaryValue('summary-run-id', runId);

      // Evaluated Sample Count
      const sampleCount = (ablData && ablData.eval_sample_count !== undefined && ablData.eval_sample_count !== null) ? ablData.eval_sample_count : (pcData ? pcData.length : null);
      this.renderSummaryValue('summary-sample-count', sampleCount);

      // Dataset SHA256 Digest
      const datasetDigest = (ablData && ablData.dataset_sha256_digest) ? ablData.dataset_sha256_digest : ((pcData && pcData.length > 0 && pcData[0].dataset_sha256_digest) ? pcData[0].dataset_sha256_digest : null);
      this.renderSummaryDigestValue('summary-dataset-digest', datasetDigest, 'Dataset SHA-256 Digest');

      // Run Records SHA256 Digest
      const recordsDigest = (ablData && ablData.run_records_sha256_digest) ? ablData.run_records_sha256_digest : null;
      this.renderSummaryDigestValue('summary-records-digest', recordsDigest, 'Run Records SHA-256 Digest');

      // Version & Seed
      this.renderSummaryValue('summary-version', ablData ? ablData.version : null);
      this.renderSummaryValue('summary-seed', (ablData && ablData.seed !== undefined && ablData.seed !== null) ? ablData.seed : null);

      // Artifact Error / Warning Alerts Container
      const alertContainer = document.getElementById('benchmark-artifacts-alert-container');
      if (alertContainer) {
        alertContainer.innerHTML = '';
        if (abl.error) {
          const ablErrCard = document.createElement('div');
          ablErrCard.className = 'status-block';
          ablErrCard.style.borderColor = 'var(--status-failed-border)';
          ablErrCard.style.backgroundColor = 'var(--status-failed-bg)';
          ablErrCard.style.fontSize = '0.8rem';
          ablErrCard.style.marginBottom = '0.5rem';

          const title = document.createElement('strong');
          title.className = 'text-danger';
          title.textContent = 'Ablation Table Artifact Status: ';

          const msg = document.createElement('span');
          msg.textContent = abl.error;

          ablErrCard.appendChild(title);
          ablErrCard.appendChild(msg);
          alertContainer.appendChild(ablErrCard);
        }

        if (pc.error) {
          const pcErrCard = document.createElement('div');
          pcErrCard.className = 'status-block';
          pcErrCard.style.borderColor = 'var(--status-failed-border)';
          pcErrCard.style.backgroundColor = 'var(--status-failed-bg)';
          pcErrCard.style.fontSize = '0.8rem';

          const title = document.createElement('strong');
          title.className = 'text-danger';
          title.textContent = 'Per-Case Results Artifact Status: ';

          const msg = document.createElement('span');
          msg.textContent = pc.error;

          pcErrCard.appendChild(title);
          pcErrCard.appendChild(msg);
          alertContainer.appendChild(pcErrCard);
        }
      }
    },

    renderSummaryValue(elementId, value) {
      const el = document.getElementById(elementId);
      if (!el) return;
      el.innerHTML = '';

      if (value !== null && value !== undefined && value !== '') {
        el.textContent = String(value);
        el.classList.remove('text-dim');
      } else {
        const span = document.createElement('span');
        span.className = 'text-dim';
        span.textContent = 'UNAVAILABLE';
        el.appendChild(span);
      }
    },

    renderSummaryDigestValue(elementId, digest, label) {
      const el = document.getElementById(elementId);
      if (!el) return;
      el.innerHTML = '';

      if (digest !== null && digest !== undefined && digest !== '') {
        const fullDigest = String(digest);
        const shortDigest = fullDigest.length > 20 ? fullDigest.substring(0, 18) + '...' : fullDigest;

        const textSpan = document.createElement('span');
        textSpan.textContent = shortDigest;
        textSpan.title = fullDigest;

        const displayLabel = label || elementId;
        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'copy-btn';
        copyBtn.style.marginLeft = '0.4rem';
        copyBtn.style.padding = '0.1rem 0.35rem';
        copyBtn.style.fontSize = '0.65rem';
        copyBtn.textContent = 'Copy';
        copyBtn.setAttribute('aria-label', `Copy ${displayLabel}`);
        copyBtn.setAttribute('title', `Copy ${displayLabel} to clipboard`);
        copyBtn.addEventListener('click', () => this.copyToClipboard(fullDigest, copyBtn));

        el.appendChild(textSpan);
        el.appendChild(copyBtn);
      } else {
        const span = document.createElement('span');
        span.className = 'text-dim';
        span.textContent = 'UNAVAILABLE';
        el.appendChild(span);
      }
    },

    // -------------------------------------------------------------------------
    // Workbench Section 2: Condition Comparisons
    // -------------------------------------------------------------------------
    renderConditionComparisons() {
      const data = this.state.benchmarkData || {};
      const abl = data.ablation_table || {};
      const ablData = abl.available ? abl.data : null;

      // 1. Baseline Performance Table
      const baselinesTbody = document.getElementById('benchmark-baselines-tbody');
      if (baselinesTbody) {
        baselinesTbody.innerHTML = '';
        if (!ablData || !ablData.baselines || typeof ablData.baselines !== 'object' || Object.keys(ablData.baselines).length === 0) {
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 10;
          td.className = 'text-center text-muted';
          td.textContent = abl.error || 'Measured baseline evaluation metrics unavailable in ablation table artifact.';
          tr.appendChild(td);
          baselinesTbody.appendChild(tr);
        } else {
          const baselines = ablData.baselines;
          Object.keys(baselines).forEach(bName => {
            const b = baselines[bName] || {};
            const cm = b.confusion_matrix;
            const ci = b.accuracy_95ci;

            const tr = document.createElement('tr');

            // Name
            const tdName = document.createElement('td');
            tdName.style.fontWeight = '600';
            tdName.textContent = bName;

            // Samples
            const tdSamples = document.createElement('td');
            tdSamples.className = 'font-mono';
            tdSamples.textContent = (b.sample_count !== undefined && b.sample_count !== null) ? String(b.sample_count) : 'UNAVAILABLE';

            // Confusion Matrix
            const tdCm = document.createElement('td');
            tdCm.className = 'font-mono';
            if (cm && typeof cm === 'object') {
              const tc = cm.TC !== undefined ? cm.TC : 'N/A';
              const fc = cm.FC !== undefined ? cm.FC : 'N/A';
              const trVal = cm.TR !== undefined ? cm.TR : 'N/A';
              const fr = cm.FR !== undefined ? cm.FR : 'N/A';
              tdCm.textContent = `TC:${tc} FC:${fc} TR:${trVal} FR:${fr}`;
            } else {
              tdCm.textContent = 'UNAVAILABLE';
            }

            // Accuracy (95% CI)
            const tdAcc = document.createElement('td');
            tdAcc.className = 'font-mono';
            if (b.accuracy_pct !== undefined && b.accuracy_pct !== null) {
              let accStr = `${b.accuracy_pct}%`;
              if (Array.isArray(ci) && ci.length >= 2) {
                accStr += ` (${ci[0]}% - ${ci[1]}%)`;
              }
              tdAcc.textContent = accStr;
            } else {
              tdAcc.textContent = 'UNAVAILABLE';
            }

            // Recall
            const tdRecall = document.createElement('td');
            tdRecall.className = 'font-mono';
            tdRecall.textContent = (b.recall_pct !== undefined && b.recall_pct !== null) ? `${b.recall_pct}%` : 'UNAVAILABLE';

            // Precision
            const tdPrec = document.createElement('td');
            tdPrec.className = 'font-mono';
            if (b.precision_pct !== undefined && b.precision_pct !== null && b.precision_pct !== 'N/A') {
              tdPrec.textContent = `${b.precision_pct}%`;
            } else if (b.precision_pct === 'N/A') {
              tdPrec.textContent = 'N/A';
            } else {
              tdPrec.textContent = 'UNAVAILABLE';
            }

            // FPR
            const tdFpr = document.createElement('td');
            tdFpr.className = 'font-mono';
            tdFpr.textContent = (b.false_positive_rate_pct !== undefined && b.false_positive_rate_pct !== null) ? `${b.false_positive_rate_pct}%` : 'UNAVAILABLE';

            // FNR
            const tdFnr = document.createElement('td');
            tdFnr.className = 'font-mono';
            tdFnr.textContent = (b.false_negative_rate_pct !== undefined && b.false_negative_rate_pct !== null) ? `${b.false_negative_rate_pct}%` : 'UNAVAILABLE';

            // Avg Latency
            const tdLat = document.createElement('td');
            tdLat.className = 'font-mono';
            tdLat.textContent = (b.avg_latency_ms !== undefined && b.avg_latency_ms !== null) ? `${b.avg_latency_ms} ms` : 'UNAVAILABLE';

            // Total Tokens Spent
            const tdTok = document.createElement('td');
            tdTok.className = 'font-mono';
            tdTok.textContent = (b.total_tokens_spent !== undefined && b.total_tokens_spent !== null) ? String(b.total_tokens_spent) : 'UNAVAILABLE';

            tr.appendChild(tdName);
            tr.appendChild(tdSamples);
            tr.appendChild(tdCm);
            tr.appendChild(tdAcc);
            tr.appendChild(tdRecall);
            tr.appendChild(tdPrec);
            tr.appendChild(tdFpr);
            tr.appendChild(tdFnr);
            tr.appendChild(tdLat);
            tr.appendChild(tdTok);

            baselinesTbody.appendChild(tr);
          });
        }
      }

      // 2. Paired McNemar Inferential Comparisons
      const mcnemarTbody = document.getElementById('benchmark-mcnemar-tbody');
      if (mcnemarTbody) {
        mcnemarTbody.innerHTML = '';
        const comps = ablData?.paired_mcnemar_comparisons;

        if (!comps || typeof comps !== 'object' || Object.keys(comps).length === 0) {
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 6;
          td.className = 'text-center text-muted';
          td.textContent = 'Paired McNemar inferential comparisons unavailable in ablation artifact.';
          tr.appendChild(td);
          mcnemarTbody.appendChild(tr);
        } else {
          Object.keys(comps).forEach(cName => {
            const c = comps[cName] || {};
            const tr = document.createElement('tr');

            const tdName = document.createElement('td');
            tdName.style.fontWeight = '600';
            tdName.style.fontSize = '0.8rem';
            tdName.textContent = cName;

            const tdDiscA = document.createElement('td');
            tdDiscA.className = 'font-mono';
            tdDiscA.textContent = (c.discordant_a_correct_b_incorrect !== undefined && c.discordant_a_correct_b_incorrect !== null) ? String(c.discordant_a_correct_b_incorrect) : 'UNAVAILABLE';

            const tdDiscB = document.createElement('td');
            tdDiscB.className = 'font-mono';
            tdDiscB.textContent = (c.discordant_a_incorrect_b_correct !== undefined && c.discordant_a_incorrect_b_correct !== null) ? String(c.discordant_a_incorrect_b_correct) : 'UNAVAILABLE';

            const tdChi2 = document.createElement('td');
            tdChi2.className = 'font-mono';
            tdChi2.textContent = (c.chi2_statistic !== undefined && c.chi2_statistic !== null) ? String(c.chi2_statistic) : 'UNAVAILABLE';

            const tdPval = document.createElement('td');
            tdPval.className = 'font-mono';
            tdPval.textContent = (c.p_value !== undefined && c.p_value !== null) ? String(c.p_value) : 'UNAVAILABLE';

            const tdSig = document.createElement('td');
            tdSig.style.fontWeight = '600';
            if (c.statistically_significant_alpha_005 === true) {
              tdSig.className = 'text-success';
              tdSig.textContent = 'YES (p < 0.05)';
            } else if (c.statistically_significant_alpha_005 === false) {
              tdSig.className = 'text-muted';
              tdSig.textContent = 'NO';
            } else {
              tdSig.textContent = 'UNAVAILABLE';
            }

            tr.appendChild(tdName);
            tr.appendChild(tdDiscA);
            tr.appendChild(tdDiscB);
            tr.appendChild(tdChi2);
            tr.appendChild(tdPval);
            tr.appendChild(tdSig);

            mcnemarTbody.appendChild(tr);
          });
        }
      }

      // 3. Threshold Sensitivity Analysis
      const thresholdsTbody = document.getElementById('benchmark-thresholds-tbody');
      if (thresholdsTbody) {
        thresholdsTbody.innerHTML = '';
        const ta = ablData?.threshold_ablations;

        if (!ta || typeof ta !== 'object' || Object.keys(ta).length === 0) {
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 7;
          td.className = 'text-center text-muted';
          td.textContent = 'Threshold sensitivity ablations unavailable in ablation artifact.';
          tr.appendChild(td);
          thresholdsTbody.appendChild(tr);
        } else {
          Object.keys(ta).forEach(k => {
            const item = ta[k] || {};
            const tr = document.createElement('tr');

            const tdZ = document.createElement('td');
            tdZ.className = 'font-mono';
            tdZ.style.fontWeight = '700';
            tdZ.textContent = (item.z_threshold !== undefined && item.z_threshold !== null) ? `Z = ${item.z_threshold}` : k;

            const tdTc = document.createElement('td');
            tdTc.className = 'font-mono';
            tdTc.textContent = item.TC !== undefined ? String(item.TC) : 'UNAVAILABLE';

            const tdFc = document.createElement('td');
            tdFc.className = 'font-mono';
            tdFc.textContent = item.FC !== undefined ? String(item.FC) : 'UNAVAILABLE';

            const tdTr = document.createElement('td');
            tdTr.className = 'font-mono';
            tdTr.textContent = item.TR !== undefined ? String(item.TR) : 'UNAVAILABLE';

            const tdFr = document.createElement('td');
            tdFr.className = 'font-mono';
            tdFr.textContent = item.FR !== undefined ? String(item.FR) : 'UNAVAILABLE';

            const tdPrec = document.createElement('td');
            tdPrec.className = 'font-mono';
            if (item.precision !== undefined && item.precision !== null && item.precision !== 'N/A') {
              tdPrec.textContent = `${item.precision}%`;
            } else if (item.precision === 'N/A') {
              tdPrec.textContent = 'N/A';
            } else {
              tdPrec.textContent = 'UNAVAILABLE';
            }

            const tdRec = document.createElement('td');
            tdRec.className = 'font-mono';
            tdRec.textContent = (item.recall !== undefined && item.recall !== null) ? `${item.recall}%` : 'UNAVAILABLE';

            tr.appendChild(tdZ);
            tr.appendChild(tdTc);
            tr.appendChild(tdFc);
            tr.appendChild(tdTr);
            tr.appendChild(tdFr);
            tr.appendChild(tdPrec);
            tr.appendChild(tdRec);

            thresholdsTbody.appendChild(tr);
          });
        }
      }
    },

    // -------------------------------------------------------------------------
    // Workbench Section 3: Per-Case Evaluation Inspector
    // -------------------------------------------------------------------------
    renderBenchmarkCasesList() {
      const listUl = document.getElementById('benchmark-case-list');
      if (!listUl) return;
      listUl.innerHTML = '';

      const data = this.state.benchmarkData || {};
      const pc = data.per_case_results || {};
      const caseList = (pc.available && Array.isArray(pc.data)) ? pc.data : [];

      if (!pc.available || caseList.length === 0) {
        const emptyLi = document.createElement('li');
        emptyLi.className = 'text-muted text-center';
        emptyLi.style.padding = '1.5rem 1rem';
        emptyLi.textContent = pc.error || 'No per-case evaluation results available.';
        listUl.appendChild(emptyLi);

        const countBadge = document.getElementById('benchmark-case-count');
        if (countBadge) countBadge.textContent = '0';
        return;
      }

      let filtered = caseList.filter(c => {
        if (!c) return false;

        // Baseline Filter
        if (this.state.caseBaselineFilter !== 'ALL' && c.baseline !== this.state.caseBaselineFilter) {
          return false;
        }

        // Outcome Filter
        if (this.state.caseOutcomeFilter !== 'ALL') {
          const targetFilter = this.state.caseOutcomeFilter.toUpperCase();
          const classification = (c.classification || '').toUpperCase();
          const actualOutcome = (c.actual_outcome || '').toUpperCase();
          const status = (c.status || c.outcome || '').toUpperCase();

          if (classification !== targetFilter && actualOutcome !== targetFilter && status !== targetFilter) {
            return false;
          }
        }

        // Search Filter
        if (this.state.caseSearchQuery) {
          const q = this.state.caseSearchQuery;
          const caseId = (c.case_id || '').toLowerCase();
          const family = (c.scenario_family || c.family || c.category || '').toLowerCase();
          const reason = (c.decision_reason || c.reason || '').toLowerCase();
          const baseline = (c.baseline || '').toLowerCase();
          const actual = (c.actual_outcome || c.status || '').toLowerCase();
          const expected = (c.expected_outcome || '').toLowerCase();

          return caseId.includes(q) || family.includes(q) || reason.includes(q) || baseline.includes(q) || actual.includes(q) || expected.includes(q);
        }

        return true;
      });

      const countBadge = document.getElementById('benchmark-case-count');
      if (countBadge) {
        const total = caseList.length;
        const visible = filtered.length;
        countBadge.textContent = total === visible ? `${total}` : `${visible} of ${total}`;
        countBadge.setAttribute('aria-label', total === visible ? `${total} cases` : `${visible} of ${total} cases shown`);
      }

      if (filtered.length === 0) {
        const emptyLi = document.createElement('li');
        emptyLi.className = 'text-muted text-center';
        emptyLi.style.padding = '1.5rem 1rem';

        const hasFilters = this.state.caseSearchQuery || this.state.caseBaselineFilter !== 'ALL' || this.state.caseOutcomeFilter !== 'ALL';
        if (hasFilters) {
          const msgSpan = document.createElement('span');
          msgSpan.style.display = 'block';
          msgSpan.style.marginBottom = '0.5rem';
          msgSpan.textContent = 'No benchmark cases match active search query or filter.';

          const clearBtn = document.createElement('button');
          clearBtn.type = 'button';
          clearBtn.className = 'btn-refresh';
          clearBtn.textContent = 'Clear Case Filters';
          clearBtn.setAttribute('aria-label', 'Clear case search query and filters');
          clearBtn.setAttribute('title', 'Clear active case search query and filters');
          clearBtn.addEventListener('click', () => {
            this.state.caseSearchQuery = '';
            this.state.caseBaselineFilter = 'ALL';
            this.state.caseOutcomeFilter = 'ALL';
            const searchInput = document.getElementById('benchmark-case-search');
            if (searchInput) {
              searchInput.value = '';
              searchInput.focus();
            }
            const baseSelect = document.getElementById('benchmark-case-baseline-filter');
            if (baseSelect) baseSelect.value = 'ALL';
            const outcomeSelect = document.getElementById('benchmark-case-outcome-filter');
            if (outcomeSelect) outcomeSelect.value = 'ALL';
            this.renderBenchmarkCasesList();
          });

          emptyLi.appendChild(msgSpan);
          emptyLi.appendChild(clearBtn);
        } else {
          emptyLi.textContent = 'No recorded benchmark case instances in artifact.';
        }

        listUl.appendChild(emptyLi);
        return;
      }

      filtered.forEach((c, index) => {
        const isSelected = this.state.selectedCaseIndex === index;

        const li = document.createElement('li');
        li.className = `trace-item ${isSelected ? 'active' : ''}`;
        li.setAttribute('role', 'option');
        li.setAttribute('tabindex', '0');
        li.setAttribute('aria-selected', isSelected ? 'true' : 'false');
        li.setAttribute('aria-label', `Benchmark case ${c.case_id || 'unnamed'}, classification ${c.classification || c.actual_outcome || 'unknown'}`);

        li.addEventListener('click', () => this.selectBenchmarkCase(c, index));
        li.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            this.selectBenchmarkCase(c, index);
          } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            const items = listUl.querySelectorAll('.trace-item');
            if (index + 1 < items.length) items[index + 1].focus();
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            const items = listUl.querySelectorAll('.trace-item');
            if (index - 1 >= 0) items[index - 1].focus();
          } else if (e.key === 'Home') {
            e.preventDefault();
            const items = listUl.querySelectorAll('.trace-item');
            if (items.length > 0) items[0].focus();
          } else if (e.key === 'End') {
            e.preventDefault();
            const items = listUl.querySelectorAll('.trace-item');
            if (items.length > 0) items[items.length - 1].focus();
          }
        });

        const headerDiv = document.createElement('div');
        headerDiv.className = 'trace-item-header';

        const idSpan = document.createElement('span');
        idSpan.className = 'font-mono';
        idSpan.style.fontWeight = '700';
        idSpan.style.fontSize = '0.8rem';
        idSpan.style.color = 'var(--accent-primary)';
        idSpan.textContent = c.case_id || 'UNNAMED_CASE';

        const badgeSpan = document.createElement('span');
        const classification = (c.classification || c.actual_outcome || 'N/A').toUpperCase();
        if (classification === 'TC') {
          badgeSpan.className = 'status-badge status-badge-verified';
          badgeSpan.textContent = 'TC';
        } else if (classification === 'TR') {
          badgeSpan.className = 'status-badge status-badge-halted';
          badgeSpan.textContent = 'TR';
        } else if (classification === 'FC' || classification === 'FR') {
          badgeSpan.className = 'status-badge status-badge-failed';
          badgeSpan.textContent = classification;
        } else {
          badgeSpan.className = 'status-badge status-badge-unknown';
          badgeSpan.textContent = classification;
        }

        headerDiv.appendChild(idSpan);
        headerDiv.appendChild(badgeSpan);

        const subDiv = document.createElement('div');
        subDiv.className = 'text-muted';
        subDiv.style.fontSize = '0.75rem';
        subDiv.style.marginTop = '0.2rem';
        subDiv.textContent = `${c.baseline || 'Default Baseline'} • ${c.scenario_family || c.family || c.category || 'Unclassified'}`;

        const metaDiv = document.createElement('div');
        metaDiv.className = 'font-mono text-dim';
        metaDiv.style.fontSize = '0.7rem';
        metaDiv.style.marginTop = '0.15rem';

        const latStr = (c.latency_ms !== undefined && c.latency_ms !== null) ? `${c.latency_ms} ms` : 'Latency unavailable';
        const tokStr = (c.tokens_consumed !== undefined && c.tokens_consumed !== null) ? `${c.tokens_consumed} tokens` : 'Tokens unavailable';
        metaDiv.textContent = `${latStr} • ${tokStr}`;

        li.appendChild(headerDiv);
        li.appendChild(subDiv);
        li.appendChild(metaDiv);
        listUl.appendChild(li);
      });
    },

    selectBenchmarkCase(caseRecord, index) {
      this.state.selectedCaseIndex = index;
      this.renderBenchmarkCasesList();

      const emptyDiv = document.getElementById('benchmark-case-empty');
      const contentDiv = document.getElementById('benchmark-case-content');

      if (!caseRecord) {
        if (emptyDiv) emptyDiv.classList.remove('hidden');
        if (contentDiv) contentDiv.classList.add('hidden');
        return;
      }

      if (emptyDiv) emptyDiv.classList.add('hidden');
      if (contentDiv) {
        contentDiv.classList.remove('hidden');
        this.renderCaseDetailInspector(caseRecord, contentDiv);
      }
    },

    renderCaseDetailInspector(c, container) {
      container.innerHTML = '';

      // Header Bar with Copy buttons
      const headerBar = document.createElement('div');
      headerBar.style.display = 'flex';
      headerBar.style.justifyContent = 'space-between';
      headerBar.style.alignItems = 'center';
      headerBar.style.marginBottom = '1rem';
      headerBar.style.flexWrap = 'wrap';
      headerBar.style.gap = '0.5rem';

      const titleGroup = document.createElement('div');
      const title = document.createElement('h3');
      title.style.fontSize = '1.05rem';
      title.style.fontWeight = '700';
      title.style.margin = '0';
      title.className = 'font-mono';
      title.textContent = `Case: ${c.case_id || 'UNNAMED_CASE'}`;
      titleGroup.appendChild(title);

      const actionBtnGroup = document.createElement('div');
      actionBtnGroup.style.display = 'flex';
      actionBtnGroup.style.gap = '0.5rem';

      const copyIdBtn = document.createElement('button');
      copyIdBtn.type = 'button';
      copyIdBtn.className = 'copy-btn';
      copyIdBtn.textContent = 'Copy Case ID';
      copyIdBtn.setAttribute('aria-label', `Copy Case ID ${c.case_id}`);
      copyIdBtn.setAttribute('title', `Copy Case ID ${c.case_id} to clipboard`);
      copyIdBtn.addEventListener('click', () => this.copyToClipboard(c.case_id, copyIdBtn));
      actionBtnGroup.appendChild(copyIdBtn);

      const copyJsonBtn = document.createElement('button');
      copyJsonBtn.type = 'button';
      copyJsonBtn.className = 'copy-btn';
      copyJsonBtn.textContent = 'Copy Record JSON';
      copyJsonBtn.setAttribute('aria-label', `Copy full JSON payload for case ${c.case_id}`);
      copyJsonBtn.setAttribute('title', `Copy JSON payload for case ${c.case_id}`);
      copyJsonBtn.addEventListener('click', () => this.copyToClipboard(JSON.stringify(c, null, 2), copyJsonBtn));
      actionBtnGroup.appendChild(copyJsonBtn);

      headerBar.appendChild(titleGroup);
      headerBar.appendChild(actionBtnGroup);
      container.appendChild(headerBar);

      // Card 1: Structured Case Metadata Breakdown
      const metaCard = document.createElement('div');
      metaCard.className = 'card mb-1';

      const metaHeader = document.createElement('div');
      metaHeader.className = 'card-header';
      metaHeader.textContent = 'Recorded Case Outcomes & Telemetry';
      metaCard.appendChild(metaHeader);

      const fieldList = [
        { label: 'Case Identifier', value: c.case_id, mono: true, copyable: true },
        { label: 'Baseline Condition', value: c.baseline, bold: true },
        { label: 'Scenario Family', value: c.scenario_family || c.family || c.category },
        { label: 'Expected Outcome', value: c.expected_outcome, mono: true },
        { label: 'Actual Outcome', value: c.actual_outcome || c.status || c.outcome, mono: true, bold: true },
        { label: 'Classification Label', value: c.classification, bold: true },
        { label: 'Decision Reason / Details', value: c.decision_reason || c.reason || c.gate_action },
        { label: 'Observed Latency', value: (c.latency_ms !== undefined && c.latency_ms !== null) ? `${c.latency_ms} ms` : null, mono: true },
        { label: 'Tokens Consumed', value: (c.tokens_consumed !== undefined && c.tokens_consumed !== null) ? `${c.tokens_consumed} tokens` : null, mono: true },
        { label: 'Run Identifier', value: c.run_id, mono: true, copyable: true },
        { label: 'Dataset SHA-256 Digest', value: c.dataset_sha256_digest, mono: true, copyable: true }
      ];

      fieldList.forEach(item => {
        const row = document.createElement('div');
        row.style.marginBottom = '0.4rem';
        row.style.fontSize = '0.8rem';
        row.style.wordBreak = 'break-all';

        const lbl = document.createElement('span');
        lbl.style.color = 'var(--text-secondary)';
        lbl.style.fontWeight = '600';
        lbl.textContent = `${item.label}: `;
        row.appendChild(lbl);

        const valSpan = document.createElement('span');
        if (item.value !== null && item.value !== undefined && item.value !== '') {
          valSpan.textContent = String(item.value);
          if (item.mono) valSpan.className = 'font-mono';
          if (item.bold) valSpan.style.fontWeight = '700';
          row.appendChild(valSpan);

          if (item.copyable) {
            const btn = document.createElement('button');
              btn.type = 'button';
            btn.className = 'copy-btn';
            btn.style.marginLeft = '0.4rem';
            btn.style.padding = '0.1rem 0.35rem';
            btn.style.fontSize = '0.65rem';
            btn.textContent = 'Copy';
            btn.setAttribute('aria-label', `Copy ${item.label}`);
              btn.setAttribute('title', `Copy ${item.label} to clipboard`);
            btn.addEventListener('click', () => this.copyToClipboard(String(item.value), btn));
            row.appendChild(btn);
          }
        } else {
          valSpan.className = 'text-dim';
          valSpan.textContent = 'UNAVAILABLE / NOT RECORDED';
          row.appendChild(valSpan);
        }

        metaCard.appendChild(row);
      });

      container.appendChild(metaCard);

      // Epistemic Notice Callout Box
      const epistemicBox = document.createElement('div');
      epistemicBox.className = 'epistemic-disclaimer-box mb-1';
      epistemicBox.textContent = 'EPISTEMIC NOTICE: Individual outcome classification labels (TC/FC/TR/FR) reflect automated harness comparison against expected target outcomes. Recorded decision reasons reflect recorded telemetry from the gate evaluation loop.';
      container.appendChild(epistemicBox);

      // Card 2: Original Raw Case Record Payload
      const jsonCard = document.createElement('div');
      jsonCard.className = 'card';

      const jsonHeader = document.createElement('div');
      jsonHeader.className = 'card-header';
      jsonHeader.textContent = 'Original Raw Case JSON Payload';
      jsonCard.appendChild(jsonHeader);

      const pre = document.createElement('pre');
      pre.className = 'inspector-block';
      pre.textContent = JSON.stringify(c, null, 2);

      jsonCard.appendChild(pre);
      container.appendChild(jsonCard);
    },

    // -------------------------------------------------------------------------
    // Workbench Section 4: Methodology & Limitations
    // -------------------------------------------------------------------------
    renderMethodologyAndLimitations() {
      const data = this.state.benchmarkData || {};
      const ablData = data.ablation_table?.available ? data.ablation_table.data : null;

      const attrContainer = document.getElementById('attribution-container');
      if (attrContainer) {
        attrContainer.innerHTML = '';
        const attr = ablData?.attribution;

        if (attr && typeof attr === 'object' && Object.keys(attr).length > 0) {
          const ul = document.createElement('ul');
          ul.style.marginLeft = '1.25rem';
          ul.style.display = 'flex';
          ul.style.flexDirection = 'column';
          ul.style.gap = '0.45rem';

          Object.keys(attr).forEach(k => {
            const li = document.createElement('li');
            li.style.fontSize = '0.825rem';

            const strong = document.createElement('strong');
            strong.textContent = `${k.replace(/_/g, ' ')}: `;

            const span = document.createElement('span');
            span.textContent = String(attr[k]);

            li.appendChild(strong);
            li.appendChild(span);
            ul.appendChild(li);
          });
          attrContainer.appendChild(ul);
        } else {
          const p = document.createElement('p');
          p.className = 'text-muted';
          p.style.fontSize = '0.825rem';
          p.textContent = 'Documented interpretive takeaways unavailable in ablation table artifact.';
          attrContainer.appendChild(p);
        }
      }
    },

    // Helper method
    setText(id, text) {
      const el = document.getElementById(id);
      if (el) el.textContent = text;
    }
  };

  ObservatoryApp.init();
});
