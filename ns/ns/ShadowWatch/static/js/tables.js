/**
 * Shadow Watch table helpers.
 */
(function (global) {
  'use strict';

  function esc(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatTime(ts) {
    if (!ts) return '—';
    try {
      const d = new Date(ts.replace('Z', ''));
      return d.toISOString().substr(11, 8);
    } catch (e) {
      return ts;
    }
  }

  function severityBadge(sev) {
    const s = esc((sev || 'LOW').toUpperCase());
    return '<span class="badge badge-' + s + '">' + s + '</span>';
  }

  function protoTag(proto) {
    const p = esc((proto || 'IP').toUpperCase());
    return '<span class="proto-tag proto-' + p + '">' + p + '</span>';
  }

  function formatFlags(flags) {
    const f = String(flags || '');
    if (f.indexOf('S') >= 0 && f.indexOf('A') < 0) {
      return '<span class="flag-syn">SYN</span>';
    }
    if (f.indexOf('A') >= 0) return '<span class="flag-other">ACK</span>';
    if (f.length > 2) return '<span class="flag-other">DATA</span>';
    return '<span class="flag-other">' + esc(f || '—') + '</span>';
  }

  function scoreBar(score) {
    const s = Math.min(100, Math.max(0, Number(score) || 0));
    const color = global.SWCharts ? global.SWCharts.severityColor(s) : '#1a1a1a';
    return (
      '<div class="score-bar"><div class="score-bar-track"><div class="score-bar-fill" style="width:' +
      s +
      '%;background:' +
      color +
      '"></div></div><span class="mono" style="font-size:10px">' +
      s +
      '</span></div>'
    );
  }

  function alertRow(a) {
    return (
      '<tr data-id="' +
      esc(a.id) +
      '"><td>' +
      severityBadge(a.severity) +
      '</td><td class="mono">' +
      esc(a.source_ip) +
      '</td><td>' +
      esc(a.attack_type) +
      '</td><td class="mono">' +
      formatTime(a.timestamp) +
      '</td></tr>'
    );
  }

  function packetRow(p) {
    const flow = esc(p.src_ip) + ' → ' + esc(p.dst_ip);
    const port =
      p.dst_port != null
        ? '<span class="mono">' + esc(p.dst_port) + '</span>'
        : '—';
    return (
      '<tr><td>' +
      protoTag(p.protocol) +
      '</td><td class="mono" style="font-size:10px">' +
      flow +
      '</td><td>' +
      port +
      '</td><td>' +
      formatFlags(p.flags) +
      '</td><td class="mono">' +
      esc(p.packet_size) +
      ' B</td></tr>'
    );
  }

  function intelRow(ip, intel) {
    intel = intel || {};
    return (
      '<tr><td class="mono">' +
      esc(ip) +
      '</td><td>' +
      esc(intel.country_code || '—') +
      '</td><td class="mono" style="font-size:10px">' +
      esc(intel.asn || '—') +
      '</td><td>' +
      scoreBar(intel.risk_score || intel.abuse_score || 0) +
      '</td></tr>'
    );
  }

  function prependRow(tbody, html, highlight) {
    const tb = typeof tbody === 'string' ? document.getElementById(tbody) : tbody;
    if (!tb) return;
    const temp = document.createElement('tbody');
    temp.innerHTML = html;
    const row = temp.firstElementChild;
    if (!row) return;
    if (highlight) row.classList.add('row-highlight');
    tb.insertBefore(row, tb.firstChild);
    while (tb.rows.length > 50) tb.deleteRow(tb.rows.length - 1);
  }

  global.SWTables = {
    esc: esc,
    formatTime: formatTime,
    severityBadge: severityBadge,
    protoTag: protoTag,
    alertRow: alertRow,
    packetRow: packetRow,
    intelRow: intelRow,
    prependRow: prependRow,
    scoreBar: scoreBar,
  };
})(window);
