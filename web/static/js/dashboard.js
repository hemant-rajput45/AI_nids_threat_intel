// SOC Real-time Dashboard Controller & Chart.js Visualizations

let attackChart = null;
let severityChart = null;

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    fetchLiveStats();
    // Refresh stats every 3 seconds
    setInterval(fetchLiveStats, 3000);
});

function initCharts() {
    // 1. Attack Type Doughnut Chart
    const ctxAttack = document.getElementById("attackTypeChart").getContext("2d");
    attackChart = new Chart(ctxAttack, {
        type: "doughnut",
        data: {
            labels: ["Normal", "DoS", "PortScan", "Probe"],
            datasets: [{
                data: [1, 0, 0, 0],
                backgroundColor: ["#10b981", "#ef4444", "#f97316", "#8b5cf6"],
                borderColor: "#111827",
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "right",
                    labels: { color: "#9ca3af", font: { size: 12 } }
                }
            }
        }
    });

    // 2. Severity Bar Chart
    const ctxSeverity = document.getElementById("severityChart").getContext("2d");
    severityChart = new Chart(ctxSeverity, {
        type: "bar",
        data: {
            labels: ["Low", "Medium", "High", "Critical"],
            datasets: [{
                label: "Incidents",
                data: [0, 0, 0, 0],
                backgroundColor: ["#10b981", "#eab308", "#f97316", "#ef4444"],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: "#9ca3af" }
                },
                y: {
                    grid: { color: "#1f2937" },
                    ticks: { color: "#9ca3af", precision: 0 },
                    beginAtZero: true
                }
            }
        }
    });
}

async function fetchLiveStats() {
    try {
        const res = await fetch("/api/stats");
        const data = await res.json();

        // Update stats numbers
        document.getElementById("stat-total").innerText = data.total_alerts || 0;
        document.getElementById("stat-critical").innerText = data.critical || 0;
        document.getElementById("stat-high").innerText = data.high || 0;
        document.getElementById("stat-packets").innerText = data.total_packets_sniffed || 0;

        // Update sniffer button & pill
        const btn = document.getElementById("btn-toggle-sniffer");
        const pill = document.getElementById("sniffer-status-pill");
        const pillText = document.getElementById("sniffer-status-text");

        if (data.is_sniffing) {
            btn.innerHTML = '<i class="fa-solid fa-stop me-1"></i> Stop Sniffer';
            btn.className = "btn btn-outline-danger btn-sm";
            pill.className = "badge bg-success p-2 d-flex align-items-center gap-2";
            pillText.innerText = "Sniffing Live Traffic";
        } else {
            btn.innerHTML = '<i class="fa-solid fa-play me-1"></i> Start Sniffer';
            btn.className = "btn btn-outline-cyan btn-sm";
            pill.className = "badge bg-secondary p-2 d-flex align-items-center gap-2";
            pillText.innerText = "Sniffer Idle";
        }

        // Update Charts
        if (data.by_attack_type && Object.keys(data.by_attack_type).length > 0) {
            const labels = Object.keys(data.by_attack_type);
            const values = Object.values(data.by_attack_type);
            attackChart.data.labels = labels;
            attackChart.data.datasets[0].data = values;
            attackChart.update();
        }

        severityChart.data.datasets[0].data = [
            data.low || 0,
            data.medium || 0,
            data.high || 0,
            data.critical || 0
        ];
        severityChart.update();

        // Fetch recent alerts table
        fetchRecentAlerts();

    } catch (err) {
        console.error("Dashboard refresh error:", err);
    }
}

async function fetchRecentAlerts() {
    try {
        const res = await fetch("/api/recent-alerts");
        const alerts = await res.json();
        const tbody = document.getElementById("live-alerts-tbody");

        if (!alerts || alerts.length === 0) {
            return;
        }

        tbody.innerHTML = alerts.map(a => `
            <tr>
                <td class="text-secondary small">${a.timestamp}</td>
                <td class="fw-mono text-cyan">${a.source_ip}</td>
                <td class="fw-mono">${a.dest_ip}:${a.dest_port || 0}</td>
                <td><span class="badge bg-dark border border-secondary text-light">${a.attack_type}</span></td>
                <td>
                    <div class="progress" style="height: 6px; width: 60px;">
                        <div class="progress-bar bg-info" style="width: ${Math.round(a.confidence * 100)}%"></div>
                    </div>
                    <span class="fs-8 text-secondary">${(a.confidence * 100).toFixed(1)}%</span>
                </td>
                <td>
                    <span class="badge ${a.threat_score > 60 ? 'bg-danger' : a.threat_score > 20 ? 'bg-warning text-dark' : 'bg-success'}">
                        ${a.threat_score}/100
                    </span>
                </td>
                <td>
                    <span class="badge badge-sev-${(a.severity || 'low').toLowerCase()}">${a.severity}</span>
                </td>
                <td>
                    <a href="/threat-lookup?ip=${a.source_ip}" class="btn btn-outline-cyan btn-xs">
                        <i class="fa-solid fa-magnifying-glass"></i> Inspect
                    </a>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Error updating alerts table:", e);
    }
}
