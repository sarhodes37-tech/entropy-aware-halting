/**
 * EpistemicOS Control Plane Observatory - Client Application.
 *
 * Implements read-only client dashboard interface for:
 * 1. System Overview Metrics & Integrity Status
 * 2. Execution Trace Explorer
 * 3. Provenance Chain Explorer
 * 4. Benchmark Workbench
 *
 * Security Directive: All dynamic data rendering must strictly use textContent
 * or DOM element creation to prevent XSS execution from untrusted event payloads.
 */

document.addEventListener('DOMContentLoaded', () => {
  const ObservatoryApp = {
    state: {
      currentTab: 'overview',
      overviewData: null,
      tracesData: [],
      selectedTraceId: null,
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
      // Tab navigation
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

      // Overview refresh
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

      const m = data.metrics || {};
      this.setText('metric-total-executions', m.total_executions !== null ? m.total_executions : 'UNAVAILABLE');
      this.setText('metric-denials', m.authorization_denials !== null ? m.authorization_denials : 'UNAVAILABLE');
      this.setText('metric-halts', m.halts !== null ? m.halts : 'UNAVAILABLE');
      this.setText('metric-failures', m.execution_failures !== null ? m.execution_failures : 'UNAVAILABLE');

      // Audit Integrity
      const auditContainer = document.getElementById('audit-integrity-status');
      if (auditContainer) {
        auditContainer.innerHTML = '';
        const ai = data.audit_integrity || {};
        const statusDiv = document.createElement('div');
        statusDiv.className = ai.status === 'VERIFIED' ? 'text-success' : (ai.status === 'UNAVAILABLE' ? 'text-muted' : 'text-danger');
        statusDiv.textContent = `Status: ${ai.status || 'UNAVAILABLE'}`;

        const msgDiv = document.createElement('div');
        msgDiv.className = 'text-muted';
        msgDiv.textContent = `Details: ${ai.message || 'None'}`;

        const countDiv = document.createElement('div');
        countDiv.className = 'text-muted';
        countDiv.textContent = `Verified Records: ${ai.records_verified ?? 0}`;

        auditContainer.appendChild(statusDiv);
        auditContainer.appendChild(msgDiv);
        auditContainer.appendChild(countDiv);
      }

      // Provenance Integrity
      const provContainer = document.getElementById('provenance-integrity-status');
      if (provContainer) {
        provContainer.innerHTML = '';
        const pi = data.provenance_integrity || {};
        const statusDiv = document.createElement('div');
        statusDiv.className = pi.status === 'VERIFIED' ? 'text-success' : (pi.status === 'UNAVAILABLE' ? 'text-muted' : 'text-danger');
        statusDiv.textContent = `Status: ${pi.status || 'UNAVAILABLE'}`;

        const msgDiv = document.createElement('div');
        msgDiv.className = 'text-muted';
        msgDiv.textContent = `Details: ${pi.message || 'None'}`;

        const countDiv = document.createElement('div');
        countDiv.className = 'text-muted';
        countDiv.textContent = `Verified Records: ${pi.records_verified ?? 0}`;

        provContainer.appendChild(statusDiv);
        provContainer.appendChild(msgDiv);
        provContainer.appendChild(countDiv);
      }
    },

    renderOverviewError(msg) {
      this.setText('metric-total-executions', 'ERROR');
      this.setText('metric-denials', 'ERROR');
      this.setText('metric-halts', 'ERROR');
      this.setText('metric-failures', 'ERROR');
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
          return corr.includes(q) || req.includes(q) || act.includes(q);
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
        emptyLi.style.padding = '1rem';

        const hasFilters = this.state.traceSearchQuery || this.state.traceFilterStatus !== 'ALL';
        if (hasFilters) {
          const msgSpan = document.createElement('span');
          msgSpan.style.display = 'block';
          msgSpan.style.marginBottom = '0.5rem';
          msgSpan.textContent = 'No execution traces match your active filter.';

          const clearBtn = document.createElement('button');
          clearBtn.type = 'button';
          clearBtn.className = 'btn-refresh';
          clearBtn.textContent = 'Clear Filters';
          clearBtn.setAttribute('aria-label', 'Clear active search query and status filter');
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
          emptyLi.textContent = 'No execution traces found.';
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
        idSpan.textContent = trace.correlation_id.substring(0, 18) + '...';

        const badgeSpan = document.createElement('span');
        badgeSpan.className = `badge badge-${trace.status}`;
        badgeSpan.textContent = trace.status;

        headerDiv.appendChild(idSpan);
        headerDiv.appendChild(badgeSpan);

        const subDiv = document.createElement('div');
        subDiv.className = 'text-muted';
        subDiv.style.fontSize = '0.75rem';
        subDiv.textContent = `${trace.action_name} ➔ ${trace.target}`;

        li.appendChild(headerDiv);
        li.appendChild(subDiv);
        traceListUl.appendChild(li);
      });
    },

    selectTrace(correlationId) {
      this.state.selectedTraceId = correlationId;
      this.renderTracesList();

      const trace = this.state.tracesData.find(t => t.correlation_id === correlationId);
      const emptyDiv = document.getElementById('trace-detail-empty');
      const contentDiv = document.getElementById('trace-detail-content');

      if (!trace) {
        if (emptyDiv) emptyDiv.classList.remove('hidden');
        if (contentDiv) contentDiv.classList.add('hidden');
        return;
      }

      if (emptyDiv) emptyDiv.classList.add('hidden');
      if (contentDiv) {
        contentDiv.classList.remove('hidden');
        contentDiv.innerHTML = '';

        // Title
        const title = document.createElement('h3');
        title.style.marginBottom = '0.5rem';
        title.textContent = `Execution Trace: ${trace.correlation_id}`;
        contentDiv.appendChild(title);

        // Metadata grid
        const metaGrid = document.createElement('div');
        metaGrid.className = 'section-grid mb-1';

        const metaCard = document.createElement('div');
        metaCard.className = 'card';
        metaCard.innerHTML = `<div class="card-header">Lifecycle Overview</div>`;

        const pStatus = document.createElement('p');
        pStatus.innerHTML = `<strong>Status:</strong> <span class="badge badge-${trace.status}">${trace.status}</span>`;
        const pAction = document.createElement('p');
        pAction.textContent = `Action Name: ${trace.action_name}`;
        const pTarget = document.createElement('p');
        pTarget.textContent = `Target: ${trace.target}`;
        const pReq = document.createElement('p');
        pReq.textContent = `Request ID: ${trace.request_id}`;

        metaCard.appendChild(pStatus);
        metaCard.appendChild(pAction);
        metaCard.appendChild(pTarget);
        metaCard.appendChild(pReq);

        // Auth Evidence
        const authCard = document.createElement('div');
        authCard.className = 'card';
        authCard.innerHTML = `<div class="card-header">Authorization Evidence</div>`;

        const ae = trace.authorization_evidence || {};
        const pAuthToken = document.createElement('p');
        pAuthToken.className = 'font-mono';
        pAuthToken.style.fontSize = '0.8rem';
        pAuthToken.textContent = `Token ID: ${ae.authorization_token_id || 'NONE'}`;

        const pDigest = document.createElement('p');
        pDigest.className = 'font-mono';
        pDigest.style.fontSize = '0.8rem';
        pDigest.textContent = `Digest: ${ae.canonical_request_digest ? ae.canonical_request_digest.substring(0, 16) + '...' : 'NONE'}`;

        const pPolicy = document.createElement('p');
        pPolicy.textContent = `Policy Version: ${ae.policy_version || 'N/A'}`;

        authCard.appendChild(pAuthToken);
        authCard.appendChild(pDigest);
        authCard.appendChild(pPolicy);

        metaGrid.appendChild(metaCard);
        metaGrid.appendChild(authCard);
        contentDiv.appendChild(metaGrid);

        // Reconciliation Report
        const recCard = document.createElement('div');
        recCard.className = 'card mb-1';
        recCard.innerHTML = `<div class="card-header">Reconciliation Status</div>`;

        const rec = trace.reconciliation || {};
        const pValid = document.createElement('p');
        pValid.className = rec.valid ? 'text-success' : 'text-danger';
        pValid.textContent = `Reconciliation Result: ${rec.status || 'UNKNOWN'}`;

        recCard.appendChild(pValid);

        if (rec.violations && rec.violations.length > 0) {
          const violTitle = document.createElement('strong');
          violTitle.className = 'text-danger';
          violTitle.textContent = 'Violations Detected:';
          recCard.appendChild(violTitle);

          const ulViol = document.createElement('ul');
          ulViol.style.marginLeft = '1.25rem';
          rec.violations.forEach(v => {
            const li = document.createElement('li');
            li.className = 'text-danger';
            li.textContent = v;
            ulViol.appendChild(li);
          });
          recCard.appendChild(ulViol);
        }
        contentDiv.appendChild(recCard);

        // Events Sequence Table
        const eventsCard = document.createElement('div');
        eventsCard.className = 'card';
        eventsCard.innerHTML = `<div class="card-header">Trace Event Timeline</div>`;

        const table = document.createElement('table');
        table.className = 'data-table';
        table.innerHTML = `
          <thead>
            <tr>
              <th>Seq #</th>
              <th>Timestamp</th>
              <th>Event Type</th>
              <th>Source</th>
              <th>Entry Hash</th>
            </tr>
          </thead>
        `;
        const tbody = document.createElement('tbody');

        (trace.provenance_events || []).forEach(ev => {
          const tr = document.createElement('tr');

          const tdSeq = document.createElement('td');
          tdSeq.textContent = ev.sequence_number ?? '-';

          const tdTs = document.createElement('td');
          tdTs.textContent = ev.timestamp || 'N/A';

          const tdType = document.createElement('td');
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
        eventsCard.appendChild(table);
        contentDiv.appendChild(eventsCard);
      }
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
        const pStatus = document.createElement('div');
        pStatus.className = pi.status === 'VERIFIED' ? 'text-success' : (pi.status === 'UNAVAILABLE' ? 'text-muted' : 'text-danger');
        pStatus.textContent = `Integrity Status: ${pi.status || 'UNAVAILABLE'}`;

        const pCount = document.createElement('div');
        pCount.className = 'text-muted';
        pCount.textContent = `Total Records Verified: ${pi.records_verified ?? 0}`;

        const pHash = document.createElement('div');
        pHash.className = 'font-mono text-muted';
        pHash.style.fontSize = '0.8rem';
        pHash.textContent = `Tail Chain Hash: ${pi.last_hash || 'NONE'}`;

        summaryDiv.appendChild(pStatus);
        summaryDiv.appendChild(pCount);
        summaryDiv.appendChild(pHash);
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
          tdSeq.textContent = ev.sequence_number ?? '-';

          const tdTs = document.createElement('td');
          tdTs.textContent = ev.timestamp || 'N/A';

          const tdType = document.createElement('td');
          tdType.textContent = ev.event_type || 'UNKNOWN';

          const tdSource = document.createElement('td');
          tdSource.textContent = ev.provenance_source || 'UNKNOWN';

          const tdCorr = document.createElement('td');
          tdCorr.className = 'font-mono';
          tdCorr.style.fontSize = '0.8rem';
          tdCorr.textContent = (ev.correlation_id || '').substring(0, 12) + '...';

          const tdTarget = document.createElement('td');
          tdTarget.textContent = ev.target || 'N/A';

          const tdHash = document.createElement('td');
          tdHash.className = 'font-mono';
          tdHash.style.fontSize = '0.75rem';
          tdHash.textContent = (ev.entry_hash || 'N/A').substring(0, 14) + '...';

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
            tdCount.textContent = b.sample_count ?? 'N/A';

            const tdCm = document.createElement('td');
            tdCm.className = 'font-mono';
            tdCm.textContent = `TC:${cm.TC ?? 0} FC:${cm.FC ?? 0} TR:${cm.TR ?? 0} FR:${cm.FR ?? 0}`;

            const tdAcc = document.createElement('td');
            tdAcc.textContent = `${(b.accuracy_pct ?? 0).toFixed(1)}% (${ci[0]}% - ${ci[1]}%)`;

            const tdFp = document.createElement('td');
            tdFp.textContent = `${(b.false_positive_rate_pct ?? 0).toFixed(1)}%`;

            const tdFn = document.createElement('td');
            tdFn.textContent = `${(b.false_negative_rate_pct ?? 0).toFixed(1)}%`;

            const tdLat = document.createElement('td');
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
            li.className = 'status-block';
            li.textContent = `${k}: Z=${item.z_threshold} ➔ TC:${item.TC} FC:${item.FC} TR:${item.TR} FR:${item.FR} (Precision: ${item.precision}%, Recall: ${item.recall}%)`;
            ul.appendChild(li);
          });
          threshContainer.appendChild(ul);
        } else {
          threshContainer.textContent = 'Threshold ablation data unavailable.';
        }
      }

      // Attribution
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
            li.style.marginBottom = '0.4rem';
            li.style.fontSize = '0.85rem';

            const strong = document.createElement('strong');
            strong.textContent = `${k.replace('_', ' ')}: `;
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

      // Per-case Results
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
            tdId.style.fontSize = '0.8rem';
            tdId.textContent = c.case_id || 'N/A';

            const tdCat = document.createElement('td');
            tdCat.textContent = c.family || c.category || 'N/A';

            const tdTarget = document.createElement('td');
            tdTarget.textContent = (c.prompt || c.action || c.target || 'N/A').substring(0, 50);

            const tdStatus = document.createElement('td');
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
