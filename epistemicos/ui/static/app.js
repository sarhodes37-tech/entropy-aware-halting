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
      benchmarkData: null,
      traceFilterStatus: 'ALL',
      traceSearchQuery: ''
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
          if (e.key === 'ArrowRight') {
            targetIndex = (index + 1) % tabs.length;
          } else if (e.key === 'ArrowLeft') {
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
          if (e.key === 'Escape' && searchInput.value) {
            searchInput.value = '';
            this.state.traceSearchQuery = '';
            this.renderTracesList();
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
    },

    switchTab(tabName) {
      this.state.currentTab = tabName;
      document.querySelectorAll('.nav-tab').forEach(btn => {
        const isActive = btn.getAttribute('data-tab') === tabName;
        btn.classList.toggle('active', isActive);
        btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
        btn.setAttribute('tabindex', isActive ? '0' : '-1');
      });
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
      navigator.clipboard.writeText(text).then(() => {
        if (btnElement) {
          const origText = btnElement.textContent;
          btnElement.textContent = 'Copied!';
          btnElement.classList.add('copied');
          setTimeout(() => {
            btnElement.textContent = origText;
            btnElement.classList.remove('copied');
          }, 1500);
        }
      }).catch(err => {
        console.error('Copy failed:', err);
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
      }
      if (refreshIcon) {
        refreshIcon.classList.add('spin');
      }

      try {
        const res = await fetch('/api/overview');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        this.state.overviewData = data;
        this.renderOverview();
      } catch (err) {
        console.error('Failed to load overview:', err);
        this.renderOverviewError(err.message);
      } finally {
        if (btnRefresh) {
          btnRefresh.disabled = false;
          btnRefresh.removeAttribute('aria-busy');
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
      this.setText('metric-total-executions', m.total_executions !== null ? m.total_executions : 'UNAVAILABLE');
      this.setText('metric-denials', m.authorization_denials !== null ? m.authorization_denials : 'UNAVAILABLE');
      this.setText('metric-halts', m.halts !== null ? m.halts : 'UNAVAILABLE');
      this.setText('metric-failures', m.execution_failures !== null ? m.execution_failures : 'UNAVAILABLE');

      // Audit Integrity Block
      const auditContainer = document.getElementById('audit-integrity-status');
      if (auditContainer) {
        auditContainer.innerHTML = '';
        const ai = data.audit_integrity || {};

        const headerDiv = document.createElement('div');
        headerDiv.style.display = 'flex';
        headerDiv.style.justifySpaceBetween = 'space-between';
        headerDiv.style.alignItems = 'center';
        headerDiv.style.marginBottom = '0.5rem';

        const labelSpan = document.createElement('span');
        labelSpan.style.fontWeight = '600';
        labelSpan.textContent = 'Audit Trail Status: ';

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

      // Provenance Integrity Block
      const provContainer = document.getElementById('provenance-integrity-status');
      if (provContainer) {
        provContainer.innerHTML = '';
        const pi = data.provenance_integrity || {};

        const headerDiv = document.createElement('div');
        headerDiv.style.display = 'flex';
        headerDiv.style.justifySpaceBetween = 'space-between';
        headerDiv.style.alignItems = 'center';
        headerDiv.style.marginBottom = '0.5rem';

        const labelSpan = document.createElement('span');
        labelSpan.style.fontWeight = '600';
        labelSpan.textContent = 'Hash Chain Integrity: ';

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
      try {
        const res = await fetch('/api/traces');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        this.state.tracesData = data;
        this.renderTracesList();
      } catch (err) {
        console.error('Failed to load traces:', err);
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
          clearBtn.addEventListener('click', () => {
            this.state.traceSearchQuery = '';
            this.state.traceFilterStatus = 'ALL';
            const searchInput = document.getElementById('trace-search');
            if (searchInput) searchInput.value = '';
            const statusFilter = document.getElementById('trace-status-filter');
            if (statusFilter) statusFilter.value = 'ALL';
            this.renderTracesList();
          });

          emptyLi.appendChild(msgSpan);
          emptyLi.appendChild(clearBtn);
        } else {
          emptyLi.textContent = 'No execution traces recorded.';
        }

        traceListUl.appendChild(emptyLi);
        return;
      }

      filtered.forEach(trace => {
        const isSelected = this.state.selectedTraceId === trace.correlation_id;
        const li = document.createElement('li');
        li.className = `trace-item ${isSelected ? 'active' : ''}`;
        li.setAttribute('role', 'button');
        li.setAttribute('tabindex', '0');
        li.setAttribute('aria-selected', isSelected ? 'true' : 'false');
        li.setAttribute('aria-label', `Execution trace ${trace.correlation_id}, status ${trace.status}`);

        li.addEventListener('click', () => this.selectTrace(trace.correlation_id));
        li.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            this.selectTrace(trace.correlation_id);
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

        li.appendChild(headerDiv);
        li.appendChild(subDiv);
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
      }
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
      title.textContent = `Trace: ${trace.correlation_id}`;

      titleGroup.appendChild(title);

      const copyCorrBtn = document.createElement('button');
      copyCorrBtn.className = 'copy-btn';
      copyCorrBtn.textContent = 'Copy Correlation ID';
      copyCorrBtn.addEventListener('click', () => this.copyToClipboard(trace.correlation_id, copyCorrBtn));

      headerBar.appendChild(titleGroup);
      headerBar.appendChild(copyCorrBtn);
      container.appendChild(headerBar);

      // Section Grid: Lifecycle Overview & Authorization Evidence
      const metaGrid = document.createElement('div');
      metaGrid.className = 'section-grid mb-1';

      // Lifecycle Card
      const metaCard = document.createElement('div');
      metaCard.className = 'card';

      const metaHeader = document.createElement('div');
      metaHeader.className = 'card-header';
      metaHeader.textContent = 'Lifecycle Overview';
      metaCard.appendChild(metaHeader);

      const pStatus = document.createElement('p');
      pStatus.style.marginBottom = '0.4rem';
      pStatus.innerHTML = `<strong>Status:</strong> `;
      const statusBadge = document.createElement('span');
      statusBadge.className = `badge badge-${trace.status || 'OUTCOME_UNKNOWN'}`;
      statusBadge.textContent = trace.status || 'UNKNOWN';
      pStatus.appendChild(statusBadge);

      const pAction = document.createElement('p');
      pAction.style.marginBottom = '0.3rem';
      pAction.style.fontSize = '0.85rem';
      pAction.textContent = `Action Name: ${trace.action_name || 'N/A'}`;

      const pTarget = document.createElement('p');
      pTarget.style.marginBottom = '0.3rem';
      pTarget.style.fontSize = '0.85rem';
      pTarget.textContent = `Target Resource: ${trace.target || 'N/A'}`;

      const pReq = document.createElement('p');
      pReq.className = 'font-mono';
      pReq.style.fontSize = '0.8rem';
      pReq.style.color = 'var(--text-secondary)';
      pReq.textContent = `Request ID: ${trace.request_id || 'N/A'}`;

      metaCard.appendChild(pStatus);
      metaCard.appendChild(pAction);
      metaCard.appendChild(pTarget);
      metaCard.appendChild(pReq);

      // Authorization Evidence Card
      const authCard = document.createElement('div');
      authCard.className = 'card';

      const authHeader = document.createElement('div');
      authHeader.className = 'card-header';
      authHeader.textContent = 'Authorization Evidence';
      authCard.appendChild(authHeader);

      const ae = trace.authorization_evidence || {};

      const pAuthToken = document.createElement('p');
      pAuthToken.className = 'font-mono';
      pAuthToken.style.fontSize = '0.8rem';
      pAuthToken.style.marginBottom = '0.3rem';
      pAuthToken.textContent = `Capability Token ID: ${ae.authorization_token_id || 'NONE'}`;

      const pDigest = document.createElement('p');
      pDigest.className = 'font-mono';
      pDigest.style.fontSize = '0.8rem';
      pDigest.style.marginBottom = '0.3rem';
      pDigest.style.wordBreak = 'break-all';
      pDigest.textContent = `Payload Digest: ${ae.canonical_request_digest || 'NONE'}`;

      const pPolicy = document.createElement('p');
      pPolicy.style.fontSize = '0.85rem';
      pPolicy.textContent = `Policy Version: ${ae.policy_version || 'N/A'}`;

      authCard.appendChild(pAuthToken);
      authCard.appendChild(pDigest);
      authCard.appendChild(pPolicy);

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

      // Event Timeline & Evidence Inspector Container
      const eventsCard = document.createElement('div');
      eventsCard.className = 'card';

      const eventsHeader = document.createElement('div');
      eventsHeader.className = 'card-header';
      eventsHeader.textContent = 'Observed Event Timeline';
      eventsCard.appendChild(eventsHeader);

      const events = trace.provenance_events || [];
      if (events.length === 0) {
        const noEv = document.createElement('p');
        noEv.className = 'text-muted text-center';
        noEv.style.padding = '1rem';
        noEv.textContent = 'No provenance events recorded for this trace.';
        eventsCard.appendChild(noEv);
      } else {
        const tableResp = document.createElement('div');
        tableResp.className = 'table-responsive';

        const table = document.createElement('table');
        table.className = 'data-table';

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
          const tr = document.createElement('tr');
          tr.className = 'clickable';
          if (this.state.selectedEventSeq === ev.sequence_number) {
            tr.style.backgroundColor = 'var(--bg-hover)';
          }

          tr.addEventListener('click', () => {
            this.state.selectedEventSeq = ev.sequence_number;
            this.renderTraceDetail(trace, container);
          });

          const tdSeq = document.createElement('td');
          tdSeq.className = 'font-mono';
          tdSeq.textContent = ev.sequence_number ?? '-';

          const tdTs = document.createElement('td');
          tdTs.className = 'font-mono';
          tdTs.style.fontSize = '0.75rem';
          tdTs.textContent = ev.timestamp || 'N/A';

          const tdType = document.createElement('td');
          tdType.style.fontWeight = '600';
          tdType.textContent = ev.event_type || 'UNKNOWN';

          const tdSource = document.createElement('td');
          tdSource.textContent = ev.provenance_source || 'UNKNOWN';

          const tdHash = document.createElement('td');
          tdHash.className = 'font-mono';
          tdHash.style.fontSize = '0.75rem';
          tdHash.textContent = ev.entry_hash ? ev.entry_hash.substring(0, 16) + '...' : 'N/A';

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

        // Evidence Inspector for Selected Event
        const selectedEv = events.find(e => e.sequence_number === this.state.selectedEventSeq) || events[0];
        if (selectedEv) {
          const inspectorBox = document.createElement('div');
          inspectorBox.style.marginTop = '1.25rem';
          inspectorBox.style.borderTop = '1px solid var(--border-default)';
          inspectorBox.style.paddingTop = '1rem';

          const inspHeader = document.createElement('div');
          inspHeader.style.display = 'flex';
          inspHeader.style.justifyContent = 'space-between';
          inspHeader.style.alignItems = 'center';
          inspHeader.style.marginBottom = '0.5rem';

          const inspTitle = document.createElement('h4');
          inspTitle.style.fontSize = '0.85rem';
          inspTitle.style.color = 'var(--accent-primary)';
          inspTitle.textContent = `Evidence Inspector: Event #${selectedEv.sequence_number} (${selectedEv.event_type})`;

          const inspCopyBtn = document.createElement('button');
          inspCopyBtn.className = 'copy-btn';
          inspCopyBtn.textContent = 'Copy Event JSON';
          inspCopyBtn.addEventListener('click', () => {
            this.copyToClipboard(JSON.stringify(selectedEv, null, 2), inspCopyBtn);
          });

          inspHeader.appendChild(inspTitle);
          inspHeader.appendChild(inspCopyBtn);

          const pre = document.createElement('pre');
          pre.className = 'inspector-block';
          pre.textContent = JSON.stringify(selectedEv, null, 2);

          inspectorBox.appendChild(inspHeader);
          inspectorBox.appendChild(pre);
          eventsCard.appendChild(inspectorBox);
        }
      }

      container.appendChild(eventsCard);
    },

    // -------------------------------------------------------------------------
    // View 3: Provenance Explorer
    // -------------------------------------------------------------------------
    async loadProvenance() {
      try {
        const res = await fetch('/api/provenance');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        this.state.provenanceData = data;
        this.renderProvenance();
      } catch (err) {
        console.error('Failed to load provenance:', err);
      }
    },

    renderProvenance() {
      const data = this.state.provenanceData;
      if (!data) return;

      const summaryDiv = document.getElementById('provenance-chain-summary');
      if (summaryDiv) {
        summaryDiv.innerHTML = '';
        const pi = data.integrity || {};

        const headerDiv = document.createElement('div');
        headerDiv.style.display = 'flex';
        headerDiv.style.alignItems = 'center';
        headerDiv.style.gap = '0.75rem';
        headerDiv.style.marginBottom = '0.5rem';

        const label = document.createElement('span');
        label.style.fontWeight = '600';
        label.textContent = 'Append-Only Chain Integrity:';

        const badge = this.createStatusBadge(pi.status || 'UNAVAILABLE');
        headerDiv.appendChild(label);
        headerDiv.appendChild(badge);

        const countDiv = document.createElement('div');
        countDiv.className = 'text-muted font-mono';
        countDiv.style.fontSize = '0.825rem';
        countDiv.textContent = `Total Verified Hash Records: ${pi.records_verified ?? 0}`;

        summaryDiv.appendChild(headerDiv);
        summaryDiv.appendChild(countDiv);

        if (pi.last_hash) {
          const hashRow = document.createElement('div');
          hashRow.style.display = 'flex';
          hashRow.style.alignItems = 'center';
          hashRow.style.gap = '0.5rem';
          hashRow.style.marginTop = '0.5rem';

          const hashText = document.createElement('span');
          hashText.className = 'font-mono text-dim';
          hashText.style.fontSize = '0.775rem';
          hashText.style.wordBreak = 'break-all';
          hashText.textContent = `Tail Chain Hash: ${pi.last_hash}`;

          const copyHashBtn = document.createElement('button');
          copyHashBtn.className = 'copy-btn';
          copyHashBtn.textContent = 'Copy Hash';
          copyHashBtn.addEventListener('click', () => this.copyToClipboard(pi.last_hash, copyHashBtn));

          hashRow.appendChild(hashText);
          hashRow.appendChild(copyHashBtn);
          summaryDiv.appendChild(hashRow);
        }
      }

      const tbody = document.getElementById('provenance-events-tbody');
      if (tbody) {
        tbody.innerHTML = '';
        const events = data.events || [];
        if (events.length === 0) {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td colspan="7" class="text-center text-muted">No provenance records available in log.</td>`;
          tbody.appendChild(tr);
          return;
        }

        events.forEach(ev => {
          const tr = document.createElement('tr');

          const tdSeq = document.createElement('td');
          tdSeq.className = 'font-mono';
          tdSeq.textContent = ev.sequence_number ?? '-';

          const tdTs = document.createElement('td');
          tdTs.className = 'font-mono';
          tdTs.style.fontSize = '0.75rem';
          tdTs.textContent = ev.timestamp || 'N/A';

          const tdType = document.createElement('td');
          tdType.style.fontWeight = '600';
          tdType.textContent = ev.event_type || 'UNKNOWN';

          const tdSource = document.createElement('td');
          tdSource.textContent = ev.provenance_source || 'UNKNOWN';

          const tdCorr = document.createElement('td');
          tdCorr.className = 'font-mono';
          tdCorr.style.fontSize = '0.775rem';
          tdCorr.textContent = (ev.correlation_id || '').substring(0, 14) + '...';
          tdCorr.title = ev.correlation_id;

          const tdTarget = document.createElement('td');
          tdTarget.textContent = ev.target || 'N/A';

          const tdHash = document.createElement('td');
          tdHash.className = 'font-mono';
          tdHash.style.fontSize = '0.75rem';
          tdHash.textContent = (ev.entry_hash || 'N/A').substring(0, 16) + '...';
          tdHash.title = ev.entry_hash;

          tr.appendChild(tdSeq);
          tr.appendChild(tdTs);
          tr.appendChild(tdType);
          tr.appendChild(tdSource);
          tr.appendChild(tdCorr);
          tr.appendChild(tdTarget);
          tr.appendChild(tdHash);
          tbody.appendChild(tr);
        });
      }
    },

    // -------------------------------------------------------------------------
    // View 4: Benchmark Workbench
    // -------------------------------------------------------------------------
    async loadBenchmarks() {
      try {
        const res = await fetch('/api/benchmarks');
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        this.state.benchmarkData = data;
        this.renderBenchmarks();
      } catch (err) {
        console.error('Failed to load benchmarks:', err);
      }
    },

    renderBenchmarks() {
      const data = this.state.benchmarkData;
      if (!data) return;

      // Baselines
      const baselinesTbody = document.getElementById('benchmark-baselines-tbody');
      if (baselinesTbody) {
        baselinesTbody.innerHTML = '';
        const abl = data.ablation_table || {};
        if (!abl.available || !abl.data || !abl.data.baselines) {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td colspan="7" class="text-center text-muted">${abl.error || 'Measured benchmark ablation data unavailable.'}</td>`;
          baselinesTbody.appendChild(tr);
        } else {
          const baselines = abl.data.baselines;
          Object.keys(baselines).forEach(name => {
            const b = baselines[name];
            const cm = b.confusion_matrix || {};
            const ci = b.accuracy_95ci || [0, 0];

            const tr = document.createElement('tr');

            const tdName = document.createElement('td');
            tdName.style.fontWeight = '600';
            tdName.textContent = name;

            const tdCount = document.createElement('td');
            tdCount.className = 'font-mono';
            tdCount.textContent = b.sample_count ?? 'N/A';

            const tdCm = document.createElement('td');
            tdCm.className = 'font-mono';
            tdCm.textContent = `TC:${cm.TC ?? 0} FC:${cm.FC ?? 0} TR:${cm.TR ?? 0} FR:${cm.FR ?? 0}`;

            const tdAcc = document.createElement('td');
            tdAcc.className = 'font-mono';
            tdAcc.textContent = `${(b.accuracy_pct ?? 0).toFixed(1)}% (${ci[0]}% - ${ci[1]}%)`;

            const tdFp = document.createElement('td');
            tdFp.className = 'font-mono';
            tdFp.textContent = `${(b.false_positive_rate_pct ?? 0).toFixed(1)}%`;

            const tdFn = document.createElement('td');
            tdFn.className = 'font-mono';
            tdFn.textContent = `${(b.false_negative_rate_pct ?? 0).toFixed(1)}%`;

            const tdLat = document.createElement('td');
            tdLat.className = 'font-mono';
            tdLat.textContent = `${(b.avg_latency_ms ?? 0).toFixed(2)} ms`;

            tr.appendChild(tdName);
            tr.appendChild(tdCount);
            tr.appendChild(tdCm);
            tr.appendChild(tdAcc);
            tr.appendChild(tdFp);
            tr.appendChild(tdFn);
            tr.appendChild(tdLat);
            baselinesTbody.appendChild(tr);
          });
        }
      }

      // Threshold Ablations
      const threshContainer = document.getElementById('threshold-ablations-container');
      if (threshContainer) {
        threshContainer.innerHTML = '';
        const abl = data.ablation_table || {};
        if (abl.available && abl.data && abl.data.threshold_ablations) {
          const ta = abl.data.threshold_ablations;
          const ul = document.createElement('ul');
          ul.style.listStyle = 'none';
          ul.style.display = 'flex';
          ul.style.flexDirection = 'column';
          ul.style.gap = '0.5rem';

          Object.keys(ta).forEach(k => {
            const item = ta[k];
            const li = document.createElement('li');
            li.className = 'status-block font-mono';
            li.style.fontSize = '0.8rem';
            li.textContent = `${k}: Z=${item.z_threshold} ➔ TC:${item.TC} FC:${item.FC} TR:${item.TR} FR:${item.FR} (Precision: ${item.precision}%, Recall: ${item.recall}%)`;
            ul.appendChild(li);
          });
          threshContainer.appendChild(ul);
        } else {
          threshContainer.textContent = 'Threshold ablation data unavailable.';
        }
      }

      // Attribution Takeaways
      const attrContainer = document.getElementById('attribution-container');
      if (attrContainer) {
        attrContainer.innerHTML = '';
        const abl = data.ablation_table || {};
        if (abl.available && abl.data && abl.data.attribution) {
          const attr = abl.data.attribution;
          const ul = document.createElement('ul');
          ul.style.marginLeft = '1.25rem';
          Object.keys(attr).forEach(k => {
            const li = document.createElement('li');
            li.style.marginBottom = '0.45rem';
            li.style.fontSize = '0.825rem';

            const strong = document.createElement('strong');
            strong.textContent = `${k.replace(/_/g, ' ')}: `;
            const span = document.createElement('span');
            span.textContent = attr[k];

            li.appendChild(strong);
            li.appendChild(span);
            ul.appendChild(li);
          });
          attrContainer.appendChild(ul);
        } else {
          attrContainer.textContent = 'Attribution takeaways unavailable.';
        }
      }

      // Per-Case Results
      const casesTbody = document.getElementById('benchmark-cases-tbody');
      if (casesTbody) {
        casesTbody.innerHTML = '';
        const pc = data.per_case_results || {};
        if (!pc.available || !pc.data || !Array.isArray(pc.data)) {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td colspan="5" class="text-center text-muted">${pc.error || 'Per-case evaluation results unavailable.'}</td>`;
          casesTbody.appendChild(tr);
        } else {
          pc.data.slice(0, 50).forEach(c => {
            const tr = document.createElement('tr');

            const tdId = document.createElement('td');
            tdId.className = 'font-mono';
            tdId.style.fontSize = '0.775rem';
            tdId.textContent = c.case_id || 'N/A';

            const tdCat = document.createElement('td');
            tdCat.textContent = c.family || c.category || 'N/A';

            const tdTarget = document.createElement('td');
            tdTarget.style.fontSize = '0.8rem';
            tdTarget.textContent = (c.prompt || c.action || c.target || 'N/A').substring(0, 50);

            const tdStatus = document.createElement('td');
            tdStatus.style.fontWeight = '600';
            tdStatus.textContent = c.status || c.outcome || 'N/A';

            const tdGate = document.createElement('td');
            tdGate.textContent = c.gate_action || c.decision || 'N/A';

            tr.appendChild(tdId);
            tr.appendChild(tdCat);
            tr.appendChild(tdTarget);
            tr.appendChild(tdStatus);
            tr.appendChild(tdGate);
            casesTbody.appendChild(tr);
          });
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
