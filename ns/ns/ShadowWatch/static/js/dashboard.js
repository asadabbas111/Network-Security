/**
 * Shadow Watch shared dashboard runtime (Socket.IO + status polling).
 */
(function () {
  'use strict';

  const socket = typeof io !== 'undefined' ? io() : null;

  function $(id) {
    return document.getElementById(id);
  }

  function fetchJson(url, opts) {
    return fetch(url, opts || {})
      .then((r) => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .catch((e) => {
        console.error(url, e);
        throw e;
      });
  }

  function updateClock() {
    const el = $('utc-clock');
    if (el) el.textContent = new Date().toUTCString().split(' ')[4] + ' UTC';
  }

  function updateStatus() {
    fetchJson('/api/status').then((s) => {
      const dot = $('engine-dot');
      if (dot) {
        dot.classList.toggle('off', !s.engine_running);
      }
      const iface = $('iface-name');
      if (iface) iface.textContent = s.interface || '—';
      const eng = $('status-engine');
      if (eng) eng.textContent = s.engine_running ? 'RUNNING' : 'STOPPED';
      const cpu = $('status-cpu');
      if (cpu) cpu.textContent = (s.cpu_percent || 0).toFixed(1) + '%';
      const mem = $('status-mem');
      if (mem) mem.textContent = (s.memory_mb || 0).toFixed(0) + ' MB';
      const db = $('status-db');
      if (db) db.textContent = (s.db_size_mb || 0).toFixed(2) + ' MB';
      const tcp = $('stat-tcp');
      const udp = $('stat-udp');
      const icmp = $('stat-icmp');
      if (tcp) tcp.textContent = 'TCP: ' + (s.tcp_count || 0);
      if (udp) udp.textContent = 'UDP: ' + (s.udp_count || 0);
      if (icmp) icmp.textContent = 'ICMP: ' + (s.icmp_count || 0);
    });
  }

  function formatUptime(sec) {
    sec = parseInt(sec, 10) || 0;
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    return (
      String(h).padStart(2, '0') +
      ':' +
      String(m).padStart(2, '0') +
      ':' +
      String(s).padStart(2, '0')
    );
  }

  function toast(level, message) {
    const container = $('toast-container');
    if (!container || !message) return;
    const el = document.createElement('div');
    el.className = 'toast ' + (level || 'info');
    const now = new Date();
    const t = now.toISOString().substr(11, 8) + ' UTC';
    el.innerHTML = '<div>' + String(message).replace(/</g, '&lt;') + '</div><span class="toast-time">' + t + '</span>';
    container.appendChild(el);
    setTimeout(function () {
      el.style.opacity = '0';
      el.style.transition = 'opacity 0.3s';
      setTimeout(function () {
        if (el.parentNode) el.parentNode.removeChild(el);
      }, 300);
    }, 5000);
    while (container.children.length > 6) {
      container.removeChild(container.firstChild);
    }
  }

  function bindStopExport() {
    const stopBtn = $('btn-stop');
    if (stopBtn) {
      stopBtn.addEventListener('click', () => {
        if (!confirm('Stop the capture engine?')) return;
        fetchJson('/api/engine/stop', { method: 'POST' })
          .then(() => {
            updateStatus();
            toast('warning', 'Capture engine stopped');
          })
          .catch(() => toast('error', 'Failed to stop engine'));
      });
    }
    const exportBtn = $('btn-export');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        toast('info', 'Exporting database...');
        window.location.href = '/api/export/db';
      });
    }
  }

  function bindSocketActivity() {
    if (!socket) return;
    socket.on('activity', function (data) {
      toast(data.level || 'info', data.message || '');
    });
    socket.on('new_alert', function () {
      /* Alert toasts come from server "activity" events to avoid duplicates */
    });
  }

  window.SW = {
    socket: socket,
    $: $,
    fetchJson: fetchJson,
    updateClock: updateClock,
    updateStatus: updateStatus,
    formatUptime: formatUptime,
    toast: toast,
  };

  document.addEventListener('DOMContentLoaded', () => {
    updateClock();
    setInterval(updateClock, 1000);
    updateStatus();
    setInterval(updateStatus, 3000);
    bindStopExport();
    bindSocketActivity();
  });
})();
