// static/script2.js
// Frontend logic for file-path based Log Analytics UI
// Requires endpoints:
//  - POST /set_watch_path          { path: "<full path>" }
//  - GET  /auto_results            -> latest analysis JSON (or {status: "no_data"})
//  - POST /analyze                (optional; kept for backward compatibility)
//  - GET  /export/<format_type>   -> download

function initializeTheme() {
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    // Use saved theme, or default to system preference, or default to light
    const theme = savedTheme || (systemPrefersDark ? 'dark' : 'light');
    setTheme(theme);

    // Update toggle button
    updateThemeToggle(theme);
}

function setTheme(theme) {
    if (theme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    } else {
        document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem('theme', theme);
}

function toggleDarkMode() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    setTheme(newTheme);
    updateThemeToggle(newTheme);

    // Update charts theme if they exist
    updateChartsTheme();

    // Add a subtle animation effect
    document.body.style.transition = 'background-color 0.3s ease, color 0.3s ease';
    setTimeout(() => {
        document.body.style.transition = '';
    }, 300);
}

function updateThemeToggle(theme) {
    const themeIcon = document.getElementById('themeIcon');
    const themeText = document.getElementById('themeText');

    if (theme === 'dark') {
        themeIcon.setAttribute('data-feather', 'moon');
        themeText.textContent = 'Dark Mode';
    } else {
        themeIcon.setAttribute('data-feather', 'sun');
        themeText.textContent = 'Light Mode';
    }

    // Re-render Feather icons
    feather.replace();
}

// Listen for system theme changes
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    // Only auto-update if user hasn't manually set a preference
    if (!localStorage.getItem('theme')) {
        const theme = e.matches ? 'dark' : 'light';
        setTheme(theme);
        updateThemeToggle(theme);
    }
});


(function () {
  // --- configuration ---
  const POLL_INTERVAL_MS = 3000; // poll /auto_results interval
  let pollTimer = null;
  let isPolling = false;
  let currentWatchedPath = null;
  let lastUpdate = null;

  // Chart.js chart instances
  let statusChart = null;
  let ipsChart = null;
  let timelineChart = null;
  let errorChart = null;

  // DOM elements (cached)
  const filePathInput = document.getElementById('filePathInput');
  const resultsGrid = document.getElementById('resultsGrid');
  const loadingEl = document.getElementById('loading');
  const progressBar = document.getElementById('progressBar');
  const progressFill = document.getElementById('progressFill');

  // canvas elements used by charts
  const statusCanvas = document.getElementById('statusChart');
  const ipsCanvas = document.getElementById('ipsChart');
  const timelineCanvas = document.getElementById('timelineChart');
  const errorCanvas = document.getElementById('errorChart');

  // --- helper UI functions ---
  function showLoading(msg) {
    if (loadingEl) {
      loadingEl.style.display = 'block';
      loadingEl.querySelector && (loadingEl.querySelector('div') && (loadingEl.querySelector('div').textContent = msg || 'Analyzing your logs...'));
    }
  }

  function hideLoading() {
    if (loadingEl) loadingEl.style.display = 'none';
  }

  function setProgress(pct) {
    if (!progressFill) return;
    const clamped = Math.max(0, Math.min(100, pct));
    progressFill.style.width = clamped + '%';
  }

  function showMessage(text) {
    // small ephemeral message — for now use alert fallback
    try {
      // create a small non-blocking message element
      const msg = document.createElement('div');
      msg.textContent = text;
      msg.style.position = 'fixed';
      msg.style.right = '16px';
      msg.style.bottom = '16px';
      msg.style.background = 'rgba(0,0,0,0.75)';
      msg.style.color = 'white';
      msg.style.padding = '8px 12px';
      msg.style.borderRadius = '6px';
      msg.style.zIndex = 9999;
      document.body.appendChild(msg);
      setTimeout(() => msg.remove(), 3500);
    } catch (e) {
      alert(text);
    }
  }

  // --- monitoring control ---
  async function startMonitoring() {
    const path = (filePathInput && filePathInput.value && filePathInput.value.trim()) || null;
    if (!path) {
      showMessage('Please enter a valid file path to monitor.');
      return;
    }

    try {
      const resp = await fetch('/set_watch_path', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path})
      });

      const data = await resp.json();
      if (!resp.ok) {
        showMessage(data.error || 'Failed to set watch path');
        return;
      }

      currentWatchedPath = data.path;
      showMessage('Now watching: ' + currentWatchedPath);

      // start polling if not already
      if (!isPolling) {
        pollTimer = setInterval(pollAutoResults, POLL_INTERVAL_MS);
        isPolling = true;
      }

      // immediately poll once
      pollAutoResults();

    } catch (err) {
      console.error('startMonitoring error', err);
      showMessage('Error starting monitor: ' + (err.message || err));
    }
  }

  async function stopMonitoring() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
      isPolling = false;
    }
    currentWatchedPath = null;
    showMessage('Stopped monitoring.');
  }

  // --- poll results ---
  async function pollAutoResults() {
    try {
      // lightweight GET
      const resp = await fetch('/auto_results', {cache: 'no-store'});
      if (!resp.ok) {
        // do not spam console when 500; show message
        console.error('auto_results returned status', resp.status);
        return;
      }
      const data = await resp.json();

      if (!data || data.status === 'no_data') {
        // nothing yet
        // optionally show a placeholder
        // clear UI?
        return;
      }
      if (!lastUpdate || lastUpdate !== data.updated_at) {
        lastUpdate = data.updated_at;
        updateUIWithAnalysis(data);  // force UI update
    }

    } catch (err) {
      console.error('pollAutoResults error', err);
    }
  }

  // --- manual analyze (optional) ---
  // This triggers set_watch_path (so the watcher scans immediately) and polls result
  async function analyzeLogs() {
    const path = (filePathInput && filePathInput.value && filePathInput.value.trim()) || null;
    if (!path) {
      showMessage('Enter file path to analyze or start monitoring first.');
      return;
    }

    // Ensure backend is watching this path (will force immediate scan)
    try {
      await fetch('/set_watch_path', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path})
      });
    } catch (e) {
      console.warn('analyzeLogs: set_watch_path error, will still try to poll', e);
    }

    // Show loading and poll until a result that matches the path is available
    showLoading('Analyzing file now...');
    setProgress(10);

    // poll in tight loop up to timeout
    const start = Date.now();
    const TIMEOUT_MS = 15000;

    while (Date.now() - start < TIMEOUT_MS) {
      try {
        const resp = await fetch('/auto_results', {cache: 'no-store'});
        if (!resp.ok) break;
        const data = await resp.json();

        if (data && data.watched_file && data.watched_file === path && !data.error) {
          // found matching analysis
          updateUIWithAnalysis(data);
          hideLoading();
          setProgress(100);
          setTimeout(() => setProgress(0), 600);
          showMessage('Analysis complete');
          return;
        } else if (data && data.error) {
          hideLoading();
          showMessage('Analysis error: ' + data.error);
          return;
        }
      } catch (err) {
        console.warn('analyzeLogs poll error', err);
      }
      // back off a bit
      await new Promise(r => setTimeout(r, 1000));
      setProgress(Math.min(90, ((Date.now() - start) / TIMEOUT_MS) * 90));
    }

    hideLoading();
    showMessage('Analysis timed out — check server logs or file permissions.');
  }

  // --- export ---
  function exportResults(format) {
    // format should be 'csv'|'txt'|'json'
    if (!format) return;
    // navigate to endpoint to trigger download
    const url = `/export/${encodeURIComponent(format)}`;
    // create invisible link to download
    const a = document.createElement('a');
    a.href = url;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => a.remove(), 1000);
  }

  // --- UI render helpers ---
  function clearAll() {
    // clear UI elements
    if (resultsGrid) resultsGrid.innerHTML = '';
    if (statusChart) { try { statusChart.destroy(); } catch(e){} statusChart = null; }
    if (ipsChart) { try { ipsChart.destroy(); } catch(e){} ipsChart = null; }
    if (timelineChart) { try { timelineChart.destroy(); } catch(e){} timelineChart = null; }
    if (errorChart) { try { errorChart.destroy(); } catch(e){} errorChart = null; }
    setProgress(0);
    hideLoading();
    showMessage('Cleared results.');
  }

  function updateUIWithAnalysis(result) {
    // Render basic summary into resultsGrid
    if (!resultsGrid) return;

    // Build HTML summary
    const summary = buildSummaryHTML(result);
    resultsGrid.innerHTML = summary;

    // Update charts
    try {
      renderStatusChart(result.status_codes || result.statusCodes || {});
      renderIPsChart(result.top_ips || []);
      renderTimelineChart(result.hourly_distribution || {});
      renderErrorChart(result);
    if (resultsSection) resultsSection.style.display = "block";
    if (chartsSection) chartsSection.style.display = "block";
    } catch (err) {
      console.error('chart render error', err);
    }
  }

function buildSummaryHTML(result) {
    const lines = [];

    // SUMMARY CARD
    lines.push(`
        <div class="result-card">
            <div class="card-title">Summary</div>

            <div class="metric">
                <div class="metric-label">Watched file</div>
                <div class="metric-value">${escapeHtml(result.watched_file || '—')}</div>
            </div>

            <div class="metric">
                <div class="metric-label">Detected format</div>
                <div class="metric-value">${escapeHtml(result.detected_format || 'unknown')}</div>
            </div>

            <div class="metric">
                <div class="metric-label">Total entries</div>
                <div class="metric-value">${escapeHtml(result.total_entries || 0)}</div>
            </div>

            <div class="metric">
                <div class="metric-label">Error count</div>
                <div class="metric-value">${escapeHtml(result.error_count || 0)}</div>
            </div>

            <div class="metric">
                <div class="metric-label">Warning count</div>
                <div class="metric-value">${escapeHtml(result.warning_count || 0)}</div>
            </div>

            ${result.analyzed_at ? `
            <div class="metric">
                <div class="metric-label">Analyzed at</div>
                <div class="metric-value">${escapeHtml(result.analyzed_at)}</div>
            </div>` : ''}

            ${result.updated_at ? `
            <div class="metric">
                <div class="metric-label">Updated at</div>
                <div class="metric-value">${escapeHtml(result.updated_at)}</div>
            </div>` : ''}
        </div>
    `);

    // TOP IPs
    if (result.top_ips && result.top_ips.length) {
        lines.push(`
            <div class="result-card">
                <div class="card-title">Top IP Addresses</div>
                <div class="top-list">
        `);

        result.top_ips.slice(0, 20).forEach(item => {
            const ip = escapeHtml(item[0] || item.ip || '');
            const count = escapeHtml(item[1] || item.count || 0);
            lines.push(`
                <div class="top-item">
                    <div class="top-name">${ip}</div>
                    <div class="top-count">${count}</div>
                </div>
            `);
        });

        lines.push(`</div></div>`);
    }

    // TOP URLs
    if (result.top_urls && result.top_urls.length) {
        lines.push(`
            <div class="result-card">
                <div class="card-title">Top URLs</div>
                <div class="top-list">
        `);

        result.top_urls.slice(0, 20).forEach(item => {
            const url = escapeHtml(item[0] || item.url || '');
            const count = escapeHtml(item[1] || item.count || 0);
            lines.push(`
                <div class="top-item">
                    <div class="top-name">${url}</div>
                    <div class="top-count">${count}</div>
                </div>
            `);
        });

        lines.push(`</div></div>`);
    }

    return lines.join("\n");
}


  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"'`=\/]/g, function (c) {
      return {
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
        "'": '&#39;', '/': '&#x2F;', '`': '&#x60;', '=': '&#x3D;'
      }[c];
    });
  }

  // --- Chart rendering functions (Chart.js) ---
  // Helper: convert status codes object or Map into labels+data arrays
  function normalizeStatusCodes(statusObj) {
    // Accepts { "200": 100, "404": 5 } or Counter-like array
    const pairs = [];
    if (!statusObj) return pairs;
    if (Array.isArray(statusObj)) {
      // maybe list of [status, count]
      statusObj.forEach(it => {
        if (Array.isArray(it) && it.length >= 2) pairs.push([String(it[0]), Number(it[1])]);
        else if (it && typeof it === 'object') pairs.push([String(it.status || it[0] || ''), Number(it.count || it[1] || 0)]);
      });
    } else if (typeof statusObj === 'object') {
      for (const k of Object.keys(statusObj)) {
        pairs.push([String(k), Number(statusObj[k] || 0)]);
      }
    }
    pairs.sort((a, b) => b[1] - a[1]);
    return pairs;
  }

  function renderStatusChart(statusObj) {
    const pairs = normalizeStatusCodes(statusObj);
    const labels = pairs.map(p => p[0]);
    const data = pairs.map(p => p[1]);

    const ctx = statusCanvas && statusCanvas.getContext ? statusCanvas.getContext('2d') : null;
    if (!ctx) return;

    if (statusChart) {
      statusChart.data.labels = labels;
      statusChart.data.datasets[0].data = data;
      statusChart.update();
      return;
    }

    statusChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          label: 'Status Codes',
          data: data,
          // Chart.js will use default colors if not specified
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom' },
          tooltip: { mode: 'index' }
        }
      }
    });
  }

  function renderIPsChart(topIPsArray) {
    // Accepts [ ["1.2.3.4", 100], ... ]
    const items = Array.isArray(topIPsArray) ? topIPsArray.slice(0, 10) : [];
    const labels = items.map(i => i[0] || i.ip || '');
    const data = items.map(i => Number(i[1] || i.count || 0));

    const ctx = ipsCanvas && ipsCanvas.getContext ? ipsCanvas.getContext('2d') : null;
    if (!ctx) return;

    if (ipsChart) {
      ipsChart.data.labels = labels;
      ipsChart.data.datasets[0].data = data;
      ipsChart.update();
      return;
    }

    ipsChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Requests',
          data: data
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        plugins: {
          legend: {display: false},
          tooltip: {mode: 'index'}
        },
        scales: {
          x: { beginAtZero: true }
        }
      }
    });
  }

  function renderTimelineChart(hourlyObj) {
    // hourlyObj: { "0": 10, "1": 20, ... } OR array-like
    const hours = [];
    const counts = [];
    for (let h = 0; h < 24; h++) {
      const key = String(h);
      const val = (hourlyObj && (hourlyObj[key] !== undefined ? hourlyObj[key] : hourlyObj[h])) || 0;
      hours.push(`${h}:00`);
      counts.push(Number(val));
    }

    const ctx = timelineCanvas && timelineCanvas.getContext ? timelineCanvas.getContext('2d') : null;
    if (!ctx) return;

    if (timelineChart) {
      timelineChart.data.labels = hours;
      timelineChart.data.datasets[0].data = counts;
      timelineChart.update();
      return;
    }

    timelineChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: hours,
        datasets: [{
          label: 'Requests per hour',
          data: counts,
          fill: false,
          tension: 0.2,
          pointRadius: 3
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {display: false}
        },
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }

  function renderErrorChart(result) {
    // Error trend: create a simple dataset based on hourly error percent if possible
    // We'll compute error rate per hour if we can: need hourly_distribution + error_count and total per hour.
    // Best-effort: if result.hourly_distribution & result.status_codes present, try to estimate 4xx/5xx per hour not available -> show a simple single-value donut with error_count vs total_entries.
    const total = Number(result.total_entries || 0);
    const errors = Number(result.error_count || 0);
    const safeTotal = Math.max(1, total);
    const errorPct = Math.round((errors / safeTotal) * 100);

    const ctx = errorCanvas && errorCanvas.getContext ? errorCanvas.getContext('2d') : null;
    if (!ctx) return;

    if (errorChart) {
      errorChart.data.labels = ['Errors', 'Non-errors'];
      errorChart.data.datasets[0].data = [errors, Math.max(0, total - errors)];
      errorChart.update();
      return;
    }

    errorChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Errors', 'Non-errors'],
        datasets: [{
          data: [errors, Math.max(0, total - errors)],
          // colors left to Chart.js defaults
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom' }
        }
      }
    });
  }

  // --- wire up UI actions (expose to global for HTML onclick handlers) ---
  window.startMonitoring = startMonitoring;
  window.stopMonitoring = stopMonitoring;
  window.analyzeLogs = analyzeLogs;
  window.exportResults = exportResults;
  window.clearAll = clearAll;


  // Initialize: hide loading, zero progress
  try { hideLoading(); } catch(e){}
  setProgress(0);

  // Optional: start polling if page loads with a filePath value
  (function autoStartIfPath() {
    try {
      const path = (filePathInput && filePathInput.value && filePathInput.value.trim()) || '';
      if (path) {
        // start monitoring silently
        // Do not spam the user — start only after a short delay
        setTimeout(() => {
          if (!isPolling) startMonitoring();
        }, 800);
      }
    } catch (e) { /* ignore */ }
  }());

})();
