// ============================================================
// IDS Dashboard - Real-time JavaScript
// ============================================================

// --- SocketIO Connection ---
const socket = io();

// --- State ---
let trafficChart = null;
let protocolChart = null;
let topIPChart = null;
let alertTypeChart = null;
let trafficData = {
    labels: [],
    packets: [],
    bytes: [],
};
const MAX_TRAFFIC_POINTS = 60; // 60 giây dữ liệu

// --- Chart.js Global Config ---
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.06)';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

// ============================================================
// INITIALIZATION
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initTabs();
    initSocketIO();
    initSnifferControls();
    loadSnifferStatus();
    createToastContainer();
    startPollingFallback();
});

// --- REST Polling Fallback ---
function startPollingFallback() {
    async function fetchStats() {
        try {
            const resp = await fetch('/api/stats');
            if (resp.ok) {
                const data = await resp.json();
                updateStats(data);
                updateTrafficChart(data);
                updateProtocolChart(data);
                updateTopIPChart(data);
                updateRecentPackets(data.recent_packets || []);
            }
        } catch (err) {
            console.error('Error fetching stats:', err);
        }
    }

    async function fetchAlerts() {
        try {
            const resp = await fetch('/api/alerts');
            if (resp.ok) {
                const alerts = await resp.json();
                const tbody = document.getElementById('alertTableBody');
                if (tbody && (tbody.children.length === 0 || document.getElementById('alertEmptyState'))) {
                    tbody.innerHTML = '';
                    alerts.forEach(alert => addAlertToTable(alert, false));
                    updateAlertCount();
                    updateAlertTypeChart();
                }
            }
        } catch (err) {
            console.error('Error fetching alerts:', err);
        }
    }

    fetchStats();
    fetchAlerts();
    setInterval(fetchStats, 1000);
    setInterval(fetchAlerts, 2000);
}

// ============================================================
// CHARTS
// ============================================================

function initCharts() {
    initTrafficChart();
    initProtocolChart();
    initTopIPChart();
    initAlertTypeChart();
}

function initTrafficChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');

    const gradientPackets = ctx.createLinearGradient(0, 0, 0, 280);
    gradientPackets.addColorStop(0, 'rgba(6, 182, 212, 0.25)');
    gradientPackets.addColorStop(1, 'rgba(6, 182, 212, 0.01)');

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets/s',
                data: [],
                borderColor: '#06b6d4',
                backgroundColor: gradientPackets,
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHoverBackgroundColor: '#06b6d4',
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: {
                    display: false,
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: 'rgba(6, 182, 212, 0.3)',
                    borderWidth: 1,
                    titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
                    bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
                    padding: 10,
                    cornerRadius: 8,
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false,
                    },
                    ticks: {
                        maxTicksLimit: 10,
                        font: { size: 10 },
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.04)',
                    },
                    ticks: {
                        font: { size: 10 },
                    }
                }
            },
            animation: {
                duration: 300,
            }
        }
    });
}

function initProtocolChart() {
    const ctx = document.getElementById('protocolChart').getContext('2d');

    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(59, 130, 246, 0.8)',
                    'rgba(139, 92, 246, 0.8)',
                    'rgba(16, 185, 129, 0.8)',
                    'rgba(245, 158, 11, 0.8)',
                    'rgba(100, 116, 139, 0.8)',
                ],
                borderColor: [
                    'rgba(59, 130, 246, 1)',
                    'rgba(139, 92, 246, 1)',
                    'rgba(16, 185, 129, 1)',
                    'rgba(245, 158, 11, 1)',
                    'rgba(100, 116, 139, 1)',
                ],
                borderWidth: 2,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        usePointStyle: true,
                        pointStyle: 'circle',
                        font: { size: 11, weight: '500' },
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 8,
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((context.raw / total) * 100).toFixed(1) : 0;
                            return ` ${context.label}: ${formatNumber(context.raw)} (${percentage}%)`;
                        }
                    }
                }
            },
            animation: {
                duration: 500,
            }
        }
    });
}

function initTopIPChart() {
    const ctx = document.getElementById('topIPChart').getContext('2d');

    topIPChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                backgroundColor: function(context) {
                    const chart = context.chart;
                    const { ctx: chartCtx, chartArea } = chart;
                    if (!chartArea) return 'rgba(6, 182, 212, 0.6)';
                    const gradient = chartCtx.createLinearGradient(0, chartArea.bottom, 0, chartArea.top);
                    gradient.addColorStop(0, 'rgba(6, 182, 212, 0.3)');
                    gradient.addColorStop(1, 'rgba(139, 92, 246, 0.8)');
                    return gradient;
                },
                borderColor: 'rgba(6, 182, 212, 0.6)',
                borderWidth: 1,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false,
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 8,
                    titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
                    bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.04)',
                    },
                    ticks: { font: { size: 10 } }
                },
                y: {
                    grid: {
                        display: false,
                    },
                    ticks: {
                        font: {
                            family: "'JetBrains Mono', monospace",
                            size: 10,
                        }
                    }
                }
            },
            animation: {
                duration: 300,
            }
        }
    });
}

function initAlertTypeChart() {
    const ctx = document.getElementById('alertTypeChart').getContext('2d');

    alertTypeChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                backgroundColor: [
                    'rgba(239, 68, 68, 0.7)',
                    'rgba(245, 158, 11, 0.7)',
                    'rgba(6, 182, 212, 0.7)',
                    'rgba(139, 92, 246, 0.7)',
                    'rgba(16, 185, 129, 0.7)',
                ],
                borderColor: [
                    'rgba(239, 68, 68, 1)',
                    'rgba(245, 158, 11, 1)',
                    'rgba(6, 182, 212, 1)',
                    'rgba(139, 92, 246, 1)',
                    'rgba(16, 185, 129, 1)',
                ],
                borderWidth: 1,
                borderRadius: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false,
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 8,
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { font: { size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.04)',
                    },
                    ticks: {
                        stepSize: 1,
                        font: { size: 10 },
                    }
                }
            },
            animation: {
                duration: 300,
            }
        }
    });
}

// ============================================================
// SOCKETIO EVENT HANDLERS
// ============================================================

function initSocketIO() {
    socket.on('connect', () => {
        console.log('✅ Connected to IDS server');
        updateConnectionStatus(true);
    });

    socket.on('disconnect', () => {
        console.log('❌ Disconnected from IDS server');
        updateConnectionStatus(false);
    });

    // Nhận cập nhật thống kê mạng
    socket.on('network_update', (data) => {
        updateStats(data);
        updateTrafficChart(data);
        updateProtocolChart(data);
        updateTopIPChart(data);
        updateRecentPackets(data.recent_packets || []);
        updateSnifferUI(data.sniffer_running);
    });

    // Nhận cảnh báo mới
    socket.on('new_alert', (alert) => {
        addAlertToTable(alert);
        updateAlertCount();
        updateAlertTypeChart();
        showToast(`🚨 ${alert.alert_type} từ ${alert.source_ip}`, 'alert');
    });

    // Nhận danh sách cảnh báo ban đầu
    socket.on('initial_alerts', (alerts) => {
        const tbody = document.getElementById('alertTableBody');
        tbody.innerHTML = '';
        alerts.forEach(alert => addAlertToTable(alert, false));
        updateAlertCount();
    });
}

// ============================================================
// SNIFFER CONTROLS
// ============================================================

function initSnifferControls() {
    const btnStart = document.getElementById('btnStartSniffer');
    const btnStop = document.getElementById('btnStopSniffer');

    btnStart.addEventListener('click', async () => {
        btnStart.disabled = true;
        try {
            const resp = await fetch('/api/sniffer/start', { method: 'POST' });
            const data = await resp.json();
            showToast(`▶ ${data.message}`, 'success');
            loadSnifferStatus();
        } catch (err) {
            showToast('❌ Lỗi khi bắt đầu sniffer', 'alert');
        }
        btnStart.disabled = false;
    });

    btnStop.addEventListener('click', async () => {
        btnStop.disabled = true;
        try {
            const resp = await fetch('/api/sniffer/stop', { method: 'POST' });
            const data = await resp.json();
            showToast(`⏹ ${data.message}`, 'info');
            loadSnifferStatus();
        } catch (err) {
            showToast('❌ Lỗi khi dừng sniffer', 'alert');
        }
        btnStop.disabled = false;
    });
}

async function loadSnifferStatus() {
    try {
        const resp = await fetch('/api/sniffer/status');
        const data = await resp.json();
        updateSnifferUI(data.running);
        document.getElementById('interfaceName').textContent = data.interface || '--';
    } catch (err) {
        console.error('Error loading sniffer status:', err);
    }
}

function updateSnifferUI(running) {
    const dot = document.getElementById('snifferDot');
    const text = document.getElementById('snifferStatusText');
    const btnStart = document.getElementById('btnStartSniffer');
    const btnStop = document.getElementById('btnStopSniffer');

    if (running) {
        dot.className = 'sniffer-dot running';
        text.textContent = 'Đang bắt gói tin';
        btnStart.style.display = 'none';
        btnStop.style.display = 'flex';
    } else {
        dot.className = 'sniffer-dot stopped';
        text.textContent = 'Đã dừng';
        btnStart.style.display = 'flex';
        btnStop.style.display = 'none';
    }
}

// ============================================================
// UI UPDATE FUNCTIONS
// ============================================================

function updateConnectionStatus(connected) {
    const badge = document.getElementById('connectionBadge');
    const statusText = badge.querySelector('.status-text');

    if (connected) {
        badge.classList.remove('disconnected');
        statusText.textContent = 'Đã kết nối';
    } else {
        badge.classList.add('disconnected');
        statusText.textContent = 'Mất kết nối';
    }
}

function updateStats(data) {
    // Update stat cards
    animateValue('totalPackets', data.total_packets || 0);
    document.getElementById('packetsPerSec').textContent = data.packets_per_second || 0;
    animateValue('totalAlerts', data.total_alerts || 0);
    document.getElementById('bytesRecv').textContent = formatBytes(data.bytes_recv || 0);

    // Update uptime
    document.getElementById('uptimeDisplay').textContent = formatUptime(data.uptime || 0);
}

function updateTrafficChart(data) {
    const now = new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    trafficData.labels.push(now);
    trafficData.packets.push(data.packets_per_second || 0);

    // Giữ tối đa MAX_TRAFFIC_POINTS điểm
    if (trafficData.labels.length > MAX_TRAFFIC_POINTS) {
        trafficData.labels.shift();
        trafficData.packets.shift();
    }

    trafficChart.data.labels = [...trafficData.labels];
    trafficChart.data.datasets[0].data = [...trafficData.packets];
    trafficChart.update('none');
}

function updateProtocolChart(data) {
    if (!data.protocol_counts) return;

    const protocols = ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'];
    const counts = protocols.map(p => data.protocol_counts[p] || 0);

    protocolChart.data.datasets[0].data = counts;
    protocolChart.update('none');
}

function updateTopIPChart(data) {
    if (!data.top_source_ips) return;

    const ips = Object.keys(data.top_source_ips).slice(0, 8);
    const counts = ips.map(ip => data.top_source_ips[ip]);

    topIPChart.data.labels = ips;
    topIPChart.data.datasets[0].data = counts;
    topIPChart.update('none');
}

function updateRecentPackets(packets) {
    const tbody = document.getElementById('packetTableBody');
    if (!packets || packets.length === 0) return;

    tbody.innerHTML = '';
    // Hiển thị packets mới nhất ở trên
    const reversedPackets = [...packets].reverse();
    reversedPackets.forEach(pkt => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">${pkt.timestamp || ''}</td>
            <td class="ip-address">${pkt.src_ip || 'N/A'}</td>
            <td class="ip-address">${pkt.dst_ip || 'N/A'}</td>
            <td><span class="protocol-badge protocol-${pkt.protocol || 'Other'}">${pkt.protocol || 'Other'}</span></td>
            <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">${pkt.size || 0}</td>
            <td class="packet-info">${pkt.info || ''}</td>
        `;
        tbody.appendChild(row);
    });
}

function addAlertToTable(alert, animate = true) {
    const tbody = document.getElementById('alertTableBody');
    const emptyState = document.getElementById('alertEmptyState');

    if (emptyState) {
        emptyState.style.display = 'none';
    }

    const severityIcons = {
        'LOW': 'ℹ️',
        'MEDIUM': '⚠️',
        'HIGH': '🔴',
        'CRITICAL': '🚨'
    };

    // Main alert row
    const row = document.createElement('tr');
    row.className = 'alert-row' + (animate ? ' alert-new' : '');

    const hasDetails = alert.details && Object.keys(alert.details).length > 0;

    row.innerHTML = `
        <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">${alert.timestamp || ''}</td>
        <td><span class="severity-badge severity-${alert.severity}">${severityIcons[alert.severity] || ''} ${alert.severity}</span></td>
        <td style="font-weight: 600; color: var(--text-primary);">${alert.alert_type || ''}</td>
        <td class="ip-address">${alert.source_ip || 'N/A'}</td>
        <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${alert.description || ''}</td>
        <td>${hasDetails ? '<button class="alert-toggle-btn" title="Xem chi tiết">▶</button>' : ''}</td>
    `;

    // Details row (hidden by default)
    let detailsRow = null;
    if (hasDetails) {
        detailsRow = document.createElement('tr');
        detailsRow.className = 'alert-details-row';
        detailsRow.style.display = 'none';

        let detailsHTML = '<td colspan="6"><div class="alert-details-content">';
        for (const [key, value] of Object.entries(alert.details)) {
            detailsHTML += `
                <div class="detail-item">
                    <span class="detail-label">${key}</span>
                    <span class="detail-value">${value}</span>
                </div>
            `;
        }
        detailsHTML += '</div></td>';
        detailsRow.innerHTML = detailsHTML;

        // Toggle details on click
        const toggleBtn = row.querySelector('.alert-toggle-btn');
        toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isVisible = detailsRow.style.display !== 'none';
            detailsRow.style.display = isVisible ? 'none' : 'table-row';
            toggleBtn.classList.toggle('expanded', !isVisible);
        });

        row.addEventListener('click', () => {
            const isVisible = detailsRow.style.display !== 'none';
            detailsRow.style.display = isVisible ? 'none' : 'table-row';
            toggleBtn.classList.toggle('expanded', !isVisible);
        });
    }

    // Thêm vào đầu bảng
    tbody.insertBefore(row, tbody.firstChild);
    if (detailsRow) {
        // Insert details row right after the main row
        row.after(detailsRow);
    }

    // Giới hạn số dòng (mỗi alert = 2 rows nếu có details)
    const allAlertRows = tbody.querySelectorAll('.alert-row');
    if (allAlertRows.length > 100) {
        // Remove oldest alerts
        for (let i = allAlertRows.length - 1; i >= 100; i--) {
            const oldRow = allAlertRows[i];
            const nextSibling = oldRow.nextElementSibling;
            if (nextSibling && nextSibling.classList.contains('alert-details-row')) {
                nextSibling.remove();
            }
            oldRow.remove();
        }
    }
}

function updateAlertCount() {
    const badge = document.getElementById('alertCountBadge');
    const tbody = document.getElementById('alertTableBody');
    if (badge && tbody) {
        const alertRows = tbody.querySelectorAll('.alert-row');
        badge.textContent = alertRows.length;
    }
}

function updateAlertTypeChart() {
    // Đếm alert theo type từ bảng
    const tbody = document.getElementById('alertTableBody');
    const rows = tbody.querySelectorAll('.alert-row');
    const typeCounts = {};

    rows.forEach(row => {
        const typeCell = row.cells[2];
        if (typeCell) {
            const type = typeCell.textContent.trim();
            if (type) {
                typeCounts[type] = (typeCounts[type] || 0) + 1;
            }
        }
    });

    const types = Object.keys(typeCounts);
    const counts = Object.values(typeCounts);

    if (types.length > 0) {
        alertTypeChart.data.labels = types;
        alertTypeChart.data.datasets[0].data = counts;
        alertTypeChart.update('none');
    }
}

// ============================================================
// TOAST NOTIFICATIONS
// ============================================================

function createToastContainer() {
    const container = document.createElement('div');
    container.className = 'toast-container';
    container.id = 'toastContainer';
    document.body.appendChild(container);
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    // Auto remove after 4 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
    }, 4000);
}

// ============================================================
// TABS
// ============================================================

function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.dataset.tab;

            // Update button states
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Update tab panes
            document.querySelectorAll('.tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            document.getElementById(targetTab).classList.add('active');
        });
    });
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function formatNumber(num) {
    if (num === undefined || num === null) return '0';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toLocaleString('vi-VN');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

function animateValue(elementId, newValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const current = parseInt(el.textContent.replace(/[,.]/g, '')) || 0;
    if (current === newValue) return;
    el.textContent = formatNumber(newValue);
}
