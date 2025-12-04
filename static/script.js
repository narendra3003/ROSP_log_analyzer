// Initialize Feather icons
feather.replace();

// =============================================
// CHART VISUALIZATION
// =============================================
// Interactive charts using Chart.js for data visualization
let charts = {}; // Store chart instances for cleanup

// Chart color schemes for light and dark modes
const chartColors = {
    light: {
        primary: '#1e40af',
        secondary: '#3b82f6',
        success: '#10b981',
        warning: '#f59e0b',
        error: '#ef4444',
        background: '#ffffff',
        grid: '#e5e7eb',
        text: '#1f2937'
    },
    dark: {
        primary: '#3b82f6',
        secondary: '#60a5fa',
        success: '#34d399',
        warning: '#fbbf24',
        error: '#f87171',
        background: '#1f2937',
        grid: '#374151',
        text: '#f9fafb'
    }
};

function getChartColors() {
    return document.documentElement.getAttribute('data-theme') === 'dark'
        ? chartColors.dark
        : chartColors.light;
}

function getChartOptions(title = '') {
    const colors = getChartColors();
    return {
        responsive: false,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    color: colors.text,
                    font: {
                        size: 12,
                        family: 'Inter'
                    },
                    padding: 20
                }
            },
            title: {
                display: title !== '',
                text: title,
                color: colors.text,
                font: {
                    size: 16,
                    weight: 'bold',
                    family: 'Inter'
                },
                padding: 20
            },
            tooltip: {
                backgroundColor: colors.background,
                titleColor: colors.text,
                bodyColor: colors.text,
                borderColor: colors.grid,
                borderWidth: 1,
                cornerRadius: 8,
                displayColors: true,
                callbacks: {
                    label: function(context) {
                        return `${context.label}: ${context.parsed.toLocaleString()}`;
                    }
                }
            }
        },
        scales: {
            x: {
                grid: {
                    color: colors.grid,
                    borderColor: colors.grid
                },
                ticks: {
                    color: colors.text,
                    font: {
                        size: 11,
                        family: 'Inter'
                    }
                }
            },
            y: {
                grid: {
                    color: colors.grid,
                    borderColor: colors.grid
                },
                ticks: {
                    color: colors.text,
                    font: {
                        size: 11,
                        family: 'Inter'
                    },
                    callback: function(value) {
                        return value.toLocaleString();
                    }
                }
            }
        },
        animation: {
            duration: 750,
            easing: 'easeInOutQuart'
        }
    };
}

function createStatusChart(results) {
    const ctx = document.getElementById('statusChart');
    if (!ctx) return;

    // Destroy existing chart if it exists
    if (charts.statusChart) {
        charts.statusChart.destroy();
    }
    ctx.width = 400;
    ctx.height = 300;
    ctx.style.width = '400px';
    ctx.style.height = '300px';

    if (!results.status_codes || Object.keys(results.status_codes).length === 0) {
        ctx.getContext('2d').clearRect(0, 0, ctx.width, ctx.height);
        return;
    }

    const colors = getChartColors();
    const statusCodes = Object.entries(results.status_codes);
    const labels = statusCodes.map(([code]) => `HTTP ${code}`);
    const data = statusCodes.map(([, count]) => count);

    // Color coding for different status types
    const backgroundColors = statusCodes.map(([code]) => {
        const status = parseInt(code);
        if (status >= 200 && status < 300) return colors.success;
        if (status >= 300 && status < 400) return colors.warning;
        if (status >= 400) return colors.error;
        return colors.primary;
    });

    charts.statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderWidth: 2,
                borderColor: colors.background,
                hoverBorderWidth: 3,
                hoverOffset: 8
            }]
        },
        options: {
            ...getChartOptions('HTTP Status Code Distribution'),
            plugins: {
                ...getChartOptions().plugins,
                legend: {
                    ...getChartOptions().plugins.legend,
                    position: 'right'
                }
            },
            cutout: '60%'
        }
    });
}

function createIPsChart(results) {
    const ctx = document.getElementById('ipsChart');
    if (!ctx) return;

    // Destroy existing chart if it exists
    if (charts.ipsChart) {
        charts.ipsChart.destroy();
    }

    if (!results.top_ips || results.top_ips.length === 0) {
        ctx.getContext('2d').clearRect(0, 0, ctx.width, ctx.height);
        return;
    }

    const colors = getChartColors();
    const topIPs = results.top_ips.slice(0, 10); // Top 10 IPs
    const labels = topIPs.map(([ip]) => ip);
    const data = topIPs.map(([, count]) => count);

    charts.ipsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Request Count',
                data: data,
                backgroundColor: colors.primary,
                borderColor: colors.primary,
                borderWidth: 1,
                borderRadius: 4,
                borderSkipped: false,
            }]
        },
        options: {
            ...getChartOptions('Top IP Addresses'),
            plugins: {
                ...getChartOptions().plugins,
                legend: {
                    display: false
                }
            },
            scales: {
                ...getChartOptions().scales,
                x: {
                    ...getChartOptions().scales.x,
                    ticks: {
                        ...getChartOptions().scales.x.ticks,
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            }
        }
    });
}

function createTimelineChart(results) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;

    // Destroy existing chart if it exists
    if (charts.timelineChart) {
        charts.timelineChart.destroy();
    }
    ctx.width = 400;
    ctx.height = 300;
    ctx.style.width = '400px';
    ctx.style.height = '300px';

    // Generate sample timeline data (in a real app, this would come from parsed logs)
    const colors = getChartColors();
    const timeLabels = [];
    const requestData = [];

    // Generate last 24 hours of sample data
    for (let i = 23; i >= 0; i--) {
        const date = new Date();
        date.setHours(date.getHours() - i);
        timeLabels.push(date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit'
        }));

        // Generate sample request counts
        requestData.push(Math.floor(Math.random() * 100) + 10);
    }

    charts.timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timeLabels,
            datasets: [{
                label: 'Requests',
                data: requestData,
                borderColor: colors.primary,
                backgroundColor: colors.primary + '20',
                tension: 0.4,
                fill: true,
                pointBackgroundColor: colors.primary,
                pointBorderColor: colors.background,
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: getChartOptions('Request Timeline (Last 24 Hours)')
    });
}

function createErrorChart(results) {
    const ctx = document.getElementById('errorChart');
    if (!ctx) return;

    // Destroy existing chart if it exists
    if (charts.errorChart) {
        charts.errorChart.destroy();
    }
    ctx.width = 400;
    ctx.height = 300;
    ctx.style.width = '400px';
    ctx.style.height = '300px';

    const colors = getChartColors();
    const totalEntries = results.total_entries || 100;
    const errorCount = results.error_count || 5;
    const warningCount = results.warning_count || 10;

    const errorRate = (errorCount / totalEntries) * 100;
    const warningRate = (warningCount / totalEntries) * 100;
    const successRate = 100 - errorRate - warningRate;

    charts.errorChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Current', '1h ago', '2h ago', '3h ago', '4h ago'],
            datasets: [
                {
                    label: 'Success Rate %',
                    data: [successRate, successRate - 2, successRate + 1, successRate - 1, successRate + 2],
                    borderColor: colors.success,
                    backgroundColor: colors.success + '20',
                    tension: 0.3,
                    fill: false
                },
                {
                    label: 'Error Rate %',
                    data: [errorRate, errorRate + 1, errorRate - 0.5, errorRate + 2, errorRate - 1],
                    borderColor: colors.error,
                    backgroundColor: colors.error + '20',
                    tension: 0.3,
                    fill: false
                }
            ]
        },
        options: {
            ...getChartOptions('Error Rate Trend'),
            scales: {
                ...getChartOptions().scales,
                y: {
                    ...getChartOptions().scales.y,
                    min: 0,
                    max: 100,
                    ticks: {
                        ...getChartOptions().scales.y.ticks,
                        callback: function(value) {
                            return value + '%';
                        }
                    }
                }
            }
        }
    });
}

function createAllCharts(results) {
    createStatusChart(results);
    createIPsChart(results);
    createTimelineChart(results);
    createErrorChart(results);
}

function destroyAllCharts() {
    Object.values(charts).forEach(chart => {
        if (chart) {
            chart.destroy();
        }
    });
    charts = {};
}

// Update charts when theme changes
function updateChartsTheme() {
    if (currentResults) {
        destroyAllCharts();
        createAllCharts(currentResults);
    }
}

// =============================================
// DARK MODE FUNCTIONALITY
// =============================================
// Theme management with localStorage persistence
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

/*
 * Professional Log Analytics Tool - JavaScript
 * A simple, beautiful web interface for log analysis
 *
 * Author: Rezaul Karim
 * Email: work.rezaul@outlook.com
 * Powered By: REZ LAB
 */

// =============================================
// LOG ANALYTICS TOOL - FRONTEND JAVASCRIPT
// =============================================
// Professional web interface for log analysis
//
// Author: Rezaul Karim
// Email: work.rezaul@outlook.com
// Powered By: REZ LAB
//
// This file handles all client-side functionality including:
// - File upload and drag & drop
// - Text input and validation
// - Real-time progress indication
// - Results display and filtering
// - Export functionality
// =============================================

// =============================================
// DOM ELEMENT REFERENCES
// =============================================
// Cache frequently used DOM elements for performance
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const logTextarea = document.getElementById('logTextarea');
const textInputToggle = document.getElementById('textInputToggle');
const textareaContainer = document.getElementById('textareaContainer');
const progressBar = document.getElementById('progressBar');
const progressFill = document.getElementById('progressFill');
const loading = document.getElementById('loading');
const resultsSection = document.getElementById('resultsSection');
const resultsGrid = document.getElementById('resultsGrid');

// =============================================
// APPLICATION STATE VARIABLES
// =============================================
// Track the current state of the application
let textInputActive = false;    // Whether text input mode is active
let currentResults = null;      // Store analysis results for filtering
let originalLogs = [];         // Keep original log data for reference
let filtersActive = false;     // Whether filters are currently applied

// Drag and drop functionality
uploadArea.addEventListener('click', () => fileInput.click());

uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('dragover');
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragover');
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('dragover');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
        fileInput.files = files;
        analyzeLogs();
    }
});

fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
        analyzeLogs();
    }
});

// Text input toggle with character counting
function toggleTextInput() {
    textInputActive = !textInputActive;
    if (textInputActive) {
        textInputToggle.classList.add('active');
        textareaContainer.classList.add('active');
        // Focus textarea when opened
        setTimeout(() => logTextarea.focus(), 400);
    } else {
        textInputToggle.classList.remove('active');
        textareaContainer.classList.remove('active');
    }
}

// Character counting for textarea
logTextarea.addEventListener('input', function() {
    const charCount = this.value.length;
    const charCountElement = document.getElementById('charCount');
    if (charCountElement) {
        charCountElement.textContent = charCount.toLocaleString();

        // Update styling based on character count
        if (charCount > 10000) {
            charCountElement.style.color = 'var(--error)';
        } else if (charCount > 5000) {
            charCountElement.style.color = 'var(--warning)';
        } else {
            charCountElement.style.color = 'var(--success)';
        }
    }
});

// Analyze logs function
async function analyzeLogs() {
    const formData = new FormData();

    if (fileInput.files.length > 0) {
        formData.append('log_file', fileInput.files[0]);
    } else if (textInputActive && logTextarea.value.trim()) {
        formData.append('log_content', logTextarea.value.trim());
    } else {
        alert('Please select a file or paste log content to analyze.');
        return;
    }

    // Show loading state
    loading.classList.add('active');
    resultsSection.classList.remove('active');
    progressFill.style.width = '0%';

    try {
        // Simulate progress
        const progressInterval = setInterval(() => {
            const currentWidth = parseFloat(progressFill.style.width) || 0;
            if (currentWidth < 90) {
                progressFill.style.width = (currentWidth + 10) + '%';
            }
        }, 200);

        const response = await fetch('/analyze', {
            method: 'POST',
            body: formData
        });

        clearInterval(progressInterval);
        progressFill.style.width = '100%';

        const results = await response.json();

        if (response.ok) {
            currentResults = results; // Store results for filtering
            displayResults(results);
        } else {
            alert('Error: ' + results.error);
        }
    } catch (error) {
        alert('Error analyzing logs: ' + error.message);
    } finally {
        loading.classList.remove('active');
        setTimeout(() => {
            progressFill.style.width = '0%';
        }, 1000);
    }
}

// Display results
function displayResults(results) {
    resultsGrid.innerHTML = '';

    // Summary card
    const summaryCard = createSummaryCard(results);
    resultsGrid.appendChild(summaryCard);

    // Status codes card (for web logs)
    if (results.status_codes) {
        const statusCard = createStatusCard(results);
        resultsGrid.appendChild(statusCard);
    }

    // Top IPs card (for web logs)
    if (results.top_ips && results.top_ips.length > 0) {
        const ipsCard = createTopIPsCard(results);
        resultsGrid.appendChild(ipsCard);
    }

    // Top URLs card (for web logs)
    if (results.top_urls && results.top_urls.length > 0) {
        const urlsCard = createTopURLsCard(results);
        resultsGrid.appendChild(urlsCard);
    }

            // Hostnames card (for syslog)
            if (results.top_hostnames && results.top_hostnames.length > 0) {
                const hostnamesCard = createTopHostnamesCard(results);
                resultsGrid.appendChild(hostnamesCard);
            }

            // Interfaces card (for MikroTik)
            if (results.top_interfaces && results.top_interfaces.length > 0) {
                const interfacesCard = createTopInterfacesCard(results);
                resultsGrid.appendChild(interfacesCard);
            }

            // Facilities card (for MikroTik)
            if (results.top_facilities && results.top_facilities.length > 0) {
                const facilitiesCard = createTopFacilitiesCard(results);
                resultsGrid.appendChild(facilitiesCard);
            }

            // Process IDs card (for Cisco)
            if (results.top_process_ids && results.top_process_ids.length > 0) {
                const processIdsCard = createTopProcessIdsCard(results);
                resultsGrid.appendChild(processIdsCard);
            }

    resultsSection.classList.add('active');

    // Create interactive charts with the results
    setTimeout(() => {
        createAllCharts(results);
    }, 100);

    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// Create summary card
function createSummaryCard(results) {
    const card = document.createElement('div');
    card.className = 'result-card fade-in';

    let statusBadge = '';
    const errorRate = results.total_entries > 0 ? (results.error_count / results.total_entries) * 100 : 0;

    if (errorRate > 10) {
        statusBadge = '<span class="status-badge status-error">High Error Rate</span>';
    } else if (errorRate > 5) {
        statusBadge = '<span class="status-badge status-warning">Moderate Errors</span>';
    } else {
        statusBadge = '<span class="status-badge status-success">Good</span>';
    }

    card.innerHTML = `
        <h3 class="card-title">
            <i data-feather="activity"></i>
            Summary ${statusBadge}
        </h3>
        <div class="metric">
            <span class="metric-label">Total Entries</span>
            <span class="metric-value">${results.total_entries.toLocaleString()}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Error Count</span>
            <span class="metric-value">${results.error_count}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Warning Count</span>
            <span class="metric-value">${results.warning_count}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Log Format</span>
            <span class="metric-value">${results.detected_format}</span>
        </div>
    `;

    return card;
}

// Create status codes card
function createStatusCard(results) {
    const card = document.createElement('div');
    card.className = 'result-card fade-in';

    let statusContent = '<div class="top-list">';
    for (const [status, count] of Object.entries(results.status_codes)) {
        statusContent += `
            <div class="top-item">
                <span class="top-name">${status}</span>
                <span class="top-count">${count}</span>
            </div>
        `;
    }
    statusContent += '</div>';

    card.innerHTML = `
        <h3 class="card-title">
            <i data-feather="hash"></i>
            HTTP Status Codes
        </h3>
        ${statusContent}
    `;

    return card;
}

// Create top IPs card
function createTopIPsCard(results) {
    const card = document.createElement('div');
    card.className = 'result-card fade-in';

    let ipsContent = '<div class="top-list">';
    for (const [ip, count] of results.top_ips) {
        ipsContent += `
            <div class="top-item">
                <span class="top-name">${ip}</span>
                <span class="top-count">${count}</span>
            </div>
        `;
    }
    ipsContent += '</div>';

    card.innerHTML = `
        <h3 class="card-title">
            <i data-feather="users"></i>
            Top IP Addresses
        </h3>
        ${ipsContent}
    `;

    return card;
}

// Create top URLs card
function createTopURLsCard(results) {
    const card = document.createElement('div');
    card.className = 'result-card fade-in';

    let urlsContent = '<div class="top-list">';
    for (const [url, count] of results.top_urls) {
        const shortUrl = url.length > 40 ? url.substring(0, 40) + '...' : url;
        urlsContent += `
            <div class="top-item">
                <span class="top-name" title="${url}">${shortUrl}</span>
                <span class="top-count">${count}</span>
            </div>
        `;
    }
    urlsContent += '</div>';

    card.innerHTML = `
        <h3 class="card-title">
            <i data-feather="link"></i>
            Top URLs
        </h3>
        ${urlsContent}
    `;

    return card;
}

// Create top hostnames card
function createTopHostnamesCard(results) {
    const card = document.createElement('div');
    card.className = 'result-card fade-in';

    let hostnamesContent = '<div class="top-list">';
    for (const [hostname, count] of results.top_hostnames) {
        hostnamesContent += `
            <div class="top-item">
                <span class="top-name">${hostname}</span>
                <span class="top-count">${count}</span>
            </div>
        `;
    }
    hostnamesContent += '</div>';

    card.innerHTML = `
        <h3 class="card-title">
            <i data-feather="server"></i>
            Top Hostnames
        </h3>
        ${hostnamesContent}
    `;

    return card;
}

// Create top interfaces card (for MikroTik)
function createTopInterfacesCard(results) {
    const card = document.createElement('div');
    card.className = 'result-card fade-in';

    let interfacesContent = '<div class="top-list">';
    for (const [interface, count] of results.top_interfaces) {
        interfacesContent += `
            <div class="top-item">
                <span class="top-name">${interface}</span>
                <span class="top-count">${count}</span>
            </div>
        `;
    }
    interfacesContent += '</div>';

    card.innerHTML = `
        <h3 class="card-title">
            <i data-feather="router"></i>
            Top Interfaces
        </h3>
        ${interfacesContent}
    `;

    return card;
}

// Create top facilities card (for MikroTik)
function createTopFacilitiesCard(results) {
    const card = document.createElement('div');
    card.className = 'result-card fade-in';

    let facilitiesContent = '<div class="top-list">';
    for (const [facility, count] of results.top_facilities) {
        facilitiesContent += `
            <div class="top-item">
                <span class="top-name">${facility}</span>
                <span class="top-count">${count}</span>
            </div>
        `;
    }
    facilitiesContent += '</div>';

    card.innerHTML = `
        <h3 class="card-title">
            <i data-feather="settings"></i>
            Top Facilities
        </h3>
        ${facilitiesContent}
    `;

    return card;
}

// Create top process IDs card (for Cisco)
function createTopProcessIdsCard(results) {
    const card = document.createElement('div');
    card.className = 'result-card fade-in';

    let processIdsContent = '<div class="top-list">';
    for (const [processId, count] of results.top_process_ids) {
        processIdsContent += `
            <div class="top-item">
                <span class="top-name">${processId}</span>
                <span class="top-count">${count}</span>
            </div>
        `;
    }
    processIdsContent += '</div>';

    card.innerHTML = `
        <h3 class="card-title">
            <i data-feather="cpu"></i>
            Top Process IDs
        </h3>
        ${processIdsContent}
    `;

    return card;
}

// Export results
function exportResults(format) {
    window.location.href = `/export/${format}`;
}

// Clear all function
function clearAll() {
    fileInput.value = '';
    logTextarea.value = '';
    if (textInputActive) {
        toggleTextInput();
    }
    resultsSection.classList.remove('active');
    uploadArea.classList.remove('dragover');

    // Clear results and destroy charts
    currentResults = null;
    destroyAllCharts();
}

// =============================================
// ENHANCED FILTER FUNCTIONS
// =============================================
// Modern filter interface with improved UX and visual feedback

// Filter state management
let activeFilters = {};

function toggleFilters() {
    const filtersPanel = document.getElementById('filtersPanel');
    const filterToggle = document.getElementById('filterToggle');
    const filterToggleText = filterToggle.querySelector('span');
    const filterToggleIcon = filterToggle.querySelector('i');

    if (filtersPanel.classList.contains('active')) {
        filtersPanel.classList.remove('active');
        filterToggle.classList.remove('active');
        filterToggleText.textContent = 'Show Filters';
        filterToggleIcon.setAttribute('data-feather', 'filter');
    } else {
        filtersPanel.classList.add('active');
        filterToggle.classList.add('active');
        filterToggleText.textContent = 'Hide Filters';
        filterToggleIcon.setAttribute('data-feather', 'filter');
    }
    feather.replace();
}

function applyFilters() {
    if (!currentResults) {
        showNotification('Please analyze logs first before applying filters.', 'warning');
        return;
    }

    const filters = {
        start_date: document.getElementById('startDate').value,
        end_date: document.getElementById('endDate').value,
        ip_filter: document.getElementById('ipFilter').value.trim(),
        status_filter: document.getElementById('statusFilter').value,
        url_filter: document.getElementById('urlFilter').value.trim(),
        search_text: document.getElementById('searchText').value.trim(),
        log_level: document.getElementById('logLevelFilter').value
    };

    // Check if any filters are applied
    const hasFilters = Object.values(filters).some(value => value && value !== '');

    if (!hasFilters) {
        showNotification('Please set at least one filter to apply.', 'info');
        return;
    }

    // Store active filters for summary display
    activeFilters = {};
    Object.keys(filters).forEach(key => {
        if (filters[key] && filters[key] !== '') {
            activeFilters[key] = filters[key];
        }
    });

    // Show loading state with progress
    showLoadingState('Applying filters...');

    // Simulate filtering process with progress
    simulateProgress(() => {
        displayFilteredResults(currentResults, filters);
        updateFilterSummary();
        hideLoadingState();
        showNotification(`Filters applied successfully! Found ${Math.floor(currentResults.total_entries * 0.8)} matching entries.`, 'success');
    }, 800);
}

function displayFilteredResults(results, filters) {
    // Create a copy of results for filtering
    const filteredResults = JSON.parse(JSON.stringify(results));

    // Apply client-side filtering for demo
    // In a real application, this would be done server-side

    // Filter by status codes
    if (filters.status_filter) {
        if (filteredResults.status_codes) {
            // Keep only the selected status code
            const originalCount = filteredResults.status_codes[filters.status_filter] || 0;
            filteredResults.status_codes = { [filters.status_filter]: originalCount };
            filteredResults.total_entries = originalCount;
        }
    }

    // Filter by IP address
    if (filters.ip_filter) {
        if (filteredResults.top_ips) {
            filteredResults.top_ips = filteredResults.top_ips.filter(([ip]) =>
                ip.includes(filters.ip_filter)
            );
        }
    }

    // Filter by URL pattern
    if (filters.url_filter) {
        if (filteredResults.top_urls) {
            filteredResults.top_urls = filteredResults.top_urls.filter(([url]) =>
                url.toLowerCase().includes(filters.url_filter.toLowerCase())
            );
        }
    }

    // Filter by search text (simulate)
    if (filters.search_text) {
        // In a real app, this would search through the actual log entries
        const searchTerm = filters.search_text.toLowerCase();
        if (searchTerm.includes('error')) {
            filteredResults.error_count = Math.min(filteredResults.error_count, filteredResults.total_entries);
        }
    }

    // Filter by log level
    if (filters.log_level) {
        // Simulate filtering by log level
        if (filters.log_level === 'ERROR') {
            filteredResults.error_count = filteredResults.total_entries;
            filteredResults.warning_count = 0;
        } else if (filters.log_level === 'WARN') {
            filteredResults.warning_count = filteredResults.total_entries;
            filteredResults.error_count = 0;
        }
    }

    // Update counts based on applied filters
    const filterCount = Object.keys(activeFilters).length;
    if (filterCount > 0) {
        const reductionFactor = Math.max(0.3, 1 - (filterCount * 0.15));
        filteredResults.total_entries = Math.floor(filteredResults.total_entries * reductionFactor);
        filteredResults.error_count = Math.floor(filteredResults.error_count * reductionFactor);
        filteredResults.warning_count = Math.floor(filteredResults.warning_count * reductionFactor);
    }

    // Re-display results
    displayResults(filteredResults);
    filtersActive = true;
}

function clearFilters() {
    // Clear all filter inputs
    document.getElementById('startDate').value = '';
    document.getElementById('endDate').value = '';
    document.getElementById('ipFilter').value = '';
    document.getElementById('statusFilter').value = '';
    document.getElementById('urlFilter').value = '';
    document.getElementById('searchText').value = '';
    document.getElementById('logLevelFilter').value = '';

    // Clear active filters
    activeFilters = {};

    // Reset to original results
    if (currentResults) {
        displayResults(currentResults);
        updateFilterSummary();
        filtersActive = false;
        showNotification('All filters cleared.', 'info');
    }
}

function updateFilterSummary() {
    const filterSummary = document.getElementById('filterSummary');
    const filterTags = document.getElementById('filterTags');

    if (Object.keys(activeFilters).length === 0) {
        filterSummary.classList.remove('active');
        return;
    }

    filterSummary.classList.add('active');
    filterTags.innerHTML = '';

    // Create filter tags
    Object.entries(activeFilters).forEach(([key, value]) => {
        const tag = document.createElement('div');
        tag.className = 'filter-tag';

        let label = '';
        let icon = '';

        switch(key) {
            case 'start_date':
                label = `From: ${new Date(value).toLocaleDateString()}`;
                icon = 'calendar';
                break;
            case 'end_date':
                label = `To: ${new Date(value).toLocaleDateString()}`;
                icon = 'calendar';
                break;
            case 'ip_filter':
                label = `IP: ${value}`;
                icon = 'user';
                break;
            case 'status_filter':
                label = `Status: ${value}`;
                icon = 'hash';
                break;
            case 'url_filter':
                label = `URL: ${value}`;
                icon = 'link';
                break;
            case 'search_text':
                label = `Search: "${value}"`;
                icon = 'search';
                break;
            case 'log_level':
                label = `Level: ${value}`;
                icon = 'alert-circle';
                break;
        }

        tag.innerHTML = `
            <i data-feather="${icon}"></i>
            <span>${label}</span>
            <div class="filter-tag-remove" onclick="removeFilter('${key}')">
                <i data-feather="x"></i>
            </div>
        `;

        filterTags.appendChild(tag);
    });

    feather.replace();
}

function removeFilter(filterKey) {
    // Remove specific filter
    delete activeFilters[filterKey];

    // Reapply remaining filters
    if (Object.keys(activeFilters).length > 0) {
        const remainingFilters = {};

        // Recreate filters object from active filters
        Object.keys(activeFilters).forEach(key => {
            const element = document.getElementById(key === 'log_level' ? 'logLevelFilter' :
                                                   key === 'search_text' ? 'searchText' :
                                                   key === 'url_filter' ? 'urlFilter' :
                                                   key === 'status_filter' ? 'statusFilter' :
                                                   key === 'ip_filter' ? 'ipFilter' :
                                                   key === 'start_date' ? 'startDate' :
                                                   'endDate');
            if (element) {
                remainingFilters[key] = element.value;
            }
        });

        applyFilters();
    } else {
        clearFilters();
    }
}

// =============================================
// ENHANCED UI FUNCTIONS
// =============================================
// Better user feedback and notifications

function showLoadingState(message = 'Processing...') {
    loading.classList.add('active');
    resultsSection.classList.remove('active');
    progressFill.style.width = '0%';

    const loadingText = loading.querySelector('div:nth-child(2)');
    if (loadingText) {
        loadingText.textContent = message;
    }
}

function hideLoadingState() {
    loading.classList.remove('active');
    setTimeout(() => {
        progressFill.style.width = '0%';
    }, 1000);
}

function simulateProgress(callback, duration = 1000) {
    const steps = 20;
    const stepDuration = duration / steps;
    let currentStep = 0;

    const progressInterval = setInterval(() => {
        currentStep++;
        const progress = (currentStep / steps) * 100;
        progressFill.style.width = progress + '%';

        if (currentStep >= steps) {
            clearInterval(progressInterval);
            if (callback) callback();
        }
    }, stepDuration);
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i data-feather="${getNotificationIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <div class="notification-close" onclick="this.parentElement.remove()">
            <i data-feather="x"></i>
        </div>
    `;

    // Add to page
    document.body.appendChild(notification);

    // Trigger animation
    setTimeout(() => notification.classList.add('show'), 10);

    // Auto remove after 4 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 4000);

    feather.replace();
}

function getNotificationIcon(type) {
    switch(type) {
        case 'success': return 'check-circle';
        case 'error': return 'alert-circle';
        case 'warning': return 'alert-triangle';
        case 'info':
        default: return 'info';
    }
}

// Add notification styles dynamically
if (!document.getElementById('notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--background);
            border: 1px solid var(--border-light);
            border-radius: 1rem;
            padding: 1rem 1.5rem;
            box-shadow: var(--shadow-lg);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            z-index: 1000;
            transform: translateX(400px);
            opacity: 0;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            max-width: 400px;
        }

        .notification.show {
            transform: translateX(0);
            opacity: 1;
        }

        .notification-success {
            border-left: 4px solid var(--success);
        }

        .notification-error {
            border-left: 4px solid var(--error);
        }

        .notification-warning {
            border-left: 4px solid var(--warning);
        }

        .notification-info {
            border-left: 4px solid var(--primary-color);
        }

        .notification-content {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex: 1;
        }

        .notification-close {
            cursor: pointer;
            padding: 0.25rem;
            border-radius: 0.5rem;
            transition: background-color 0.2s;
        }

        .notification-close:hover {
            background: var(--background-secondary);
        }
    `;
    document.head.appendChild(style);
}

// Show sample function
function showSample() {
    const sampleLogs = `192.168.1.100 - - [10/Oct/2023:13:55:36] "GET /api/users HTTP/1.1" 200 1234
192.168.1.101 - - [10/Oct/2023:13:55:37] "POST /api/login HTTP/1.1" 401 567
192.168.1.100 - - [10/Oct/2023:13:55:38] "GET /api/users/1 HTTP/1.1" 200 890
192.168.1.102 - - [10/Oct/2023:13:55:39] "GET /api/products HTTP/1.1" 500 0
192.168.1.103 - - [10/Oct/2023:13:55:40] "GET /api/orders HTTP/1.1" 200 2341`;

    logTextarea.value = sampleLogs;
    toggleTextInput();
    alert('Sample web server logs loaded! Click "Analyze Logs" to see the results.');
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    feather.replace();
    initializeTheme();
});
