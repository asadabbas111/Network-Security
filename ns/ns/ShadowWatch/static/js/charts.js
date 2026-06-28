/**
 * Shadow Watch chart helpers (Chart.js + SVG timeline).
 */
(function (global) {
  'use strict';

  function severityColor(score) {
    if (score >= 80) return '#c0392b';
    if (score >= 60) return '#d35400';
    if (score >= 40) return '#b7791f';
    return '#2563eb';
  }

  function renderBarChart(containerId, items) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = '';
    if (!items || !items.length) {
      el.innerHTML = '<p class="muted">No attack data yet.</p>';
      return;
    }
    const max = Math.max(...items.map((i) => i.count), 1);
    items.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'bar-chart-row';
      const pct = Math.round((item.count / max) * 100);
      row.innerHTML =
        '<div class="bar-label"><span>' +
        item.attack_type +
        '</span><span class="mono">' +
        item.count +
        '</span></div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' +
        pct +
        '%"></div></div>';
      el.appendChild(row);
    });
  }

  function renderSeverityGrid(counts) {
    const ids = ['sev-critical', 'sev-high', 'sev-medium', 'sev-low'];
    const keys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    keys.forEach((k, i) => {
      const el = document.getElementById(ids[i]);
      if (el) el.textContent = (counts && counts[k]) || 0;
    });
  }

  function renderTimelineSvg(svgId, points) {
    const svg = document.getElementById(svgId);
    if (!svg) return;
    const w = svg.clientWidth || 400;
    const h = 80;
    svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
    const data = (points || []).slice(-60);
    while (data.length < 60) data.unshift({ count: 0 });
    const max = Math.max(...data.map((p) => p.count), 1);
    const step = w / (data.length - 1 || 1);
    let line = '';
    let area = '0,' + h + ' ';
    data.forEach((p, i) => {
      const x = i * step;
      const y = h - (p.count / max) * (h - 8) - 4;
      line += (i ? ' ' : '') + x + ',' + y;
      area += x + ',' + y + ' ';
    });
    area += w + ',' + h;
    svg.innerHTML =
      '<polygon points="' +
      area +
      '"></polygon><polyline points="' +
      line +
      '"></polyline>';
  }

  function initTrafficChart(canvasId) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !global.Chart) return null;
    return new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'pkt/s',
            data: [],
            borderColor: '#1a1a1a',
            backgroundColor: 'transparent',
            yAxisID: 'y',
            tension: 0.3,
            pointRadius: 0,
          },
          {
            label: 'MB/s',
            data: [],
            borderColor: '#555555',
            backgroundColor: 'transparent',
            yAxisID: 'y1',
            tension: 0.3,
            pointRadius: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
          x: { display: true, ticks: { maxTicksLimit: 8, font: { size: 9 } } },
          y: {
            type: 'linear',
            position: 'left',
            title: { display: true, text: 'pkt/s', font: { size: 9 } },
          },
          y1: {
            type: 'linear',
            position: 'right',
            grid: { drawOnChartArea: false },
            title: { display: true, text: 'MB/s', font: { size: 9 } },
          },
        },
        plugins: { legend: { labels: { font: { size: 10 } } } },
      },
    });
  }

  function pushTrafficPoint(chart, pps, mbps) {
    if (!chart) return;
    const now = new Date().toLocaleTimeString();
    chart.data.labels.push(now);
    chart.data.datasets[0].data.push(pps);
    chart.data.datasets[1].data.push(mbps);
    if (chart.data.labels.length > 60) {
      chart.data.labels.shift();
      chart.data.datasets[0].data.shift();
      chart.data.datasets[1].data.shift();
    }
    chart.update('none');
  }

  function renderHeatmap(containerId, grid) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = '';
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const labels = document.createElement('div');
    labels.className = 'heatmap-labels';
    days.forEach((d) => {
      const s = document.createElement('span');
      s.textContent = d;
      labels.appendChild(s);
    });
    el.appendChild(labels);
    const colors = ['#f0f0f0', '#d0d8e8', '#a0b4cc', '#6a8aaa', '#3a5a7a', '#1a1a1a'];
    for (let h = 0; h < 24; h++) {
      const row = document.createElement('div');
      row.className = 'heatmap';
      row.style.marginBottom = '2px';
      for (let d = 0; d < 7; d++) {
        const v = (grid && grid[h] && grid[h][d]) || 0;
        let idx = 0;
        if (v > 0) idx = 1;
        if (v > 2) idx = 2;
        if (v > 5) idx = 3;
        if (v > 10) idx = 4;
        if (v > 20) idx = 5;
        const cell = document.createElement('div');
        cell.className = 'heatmap-cell';
        cell.style.background = colors[idx];
        cell.title = 'Hour ' + h + ' ' + days[d] + ': ' + v;
        row.appendChild(cell);
      }
      el.appendChild(row);
    }
  }

  global.SWCharts = {
    severityColor: severityColor,
    renderBarChart: renderBarChart,
    renderSeverityGrid: renderSeverityGrid,
    renderTimelineSvg: renderTimelineSvg,
    initTrafficChart: initTrafficChart,
    pushTrafficPoint: pushTrafficPoint,
    renderHeatmap: renderHeatmap,
  };
})(window);
