import { useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, Search, SlidersHorizontal } from 'lucide-react';
import { count, query, request, time } from '../api';

export default function PacketAnalyzerTable({ capture, filters, onFilters, page, setPage }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  useEffect(() => {
    if (!capture) { setResult(null); return; }
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    const timer = setTimeout(() => {
      request(`/packets?${query({ ...filters, page, page_size: 8, analysis_id: capture.id })}`, { signal: controller.signal })
        .then(data => { setResult(data); setLoading(false); })
        .catch(err => { if (err.name !== 'AbortError') { setError(err.message); setLoading(false); } });
    }, 180);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [capture?.id, filters.mac, filters.attack_type, filters.severity, page]);
  const items = result?.analysis_id === capture?.id ? result?.items || [] : [];
  const total = result?.analysis_id === capture?.id ? result?.total || 0 : 0;
  const filtered = Object.values(filters).some(Boolean);
  return <section className="panel packet-panel" id="packets" aria-labelledby="packets-heading">
    <div className="panel-heading"><div><h2 id="packets-heading">Packet inspection</h2><p>Explore the frames behind each detection</p></div><span className="subtle-label">{capture ? `${count(capture.total_packets)} frames` : 'No capture loaded'}</span></div>
    <div className="table-toolbar">
      <div className="search-field"><Search size={16} /><input aria-label="Search MAC address" placeholder="Search MAC address…" value={filters.mac} onChange={event => onFilters({ ...filters, mac: event.target.value })} maxLength={64} /></div>
      <div className="table-selects"><SlidersHorizontal size={15} className="muted" />
        <select aria-label="Filter attack type" value={filters.attack_type} onChange={event => onFilters({ ...filters, attack_type: event.target.value })}><option value="">All attack types</option><option value="suspected_rogue_ap">Rogue-AP activity</option><option value="suspected_evil_twin">Suspected evil twin</option><option value="not_evaluated">Context only</option><option value="no_detection">No detection</option></select>
        <select aria-label="Filter severity" value={filters.severity} onChange={event => onFilters({ ...filters, severity: event.target.value })}><option value="">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
        {filtered && <button className="text-button" onClick={() => onFilters({ mac: '', attack_type: '', severity: '' })}>Clear</button>}
      </div>
    </div>
    <div className="table-scroll" aria-busy={loading}>
      <table><thead><tr><th>Packet</th><th>Time <span>UTC</span></th><th>BSSID / source MAC</th><th>SSID</th><th>RSSI</th><th>Detection</th><th>Severity</th></tr></thead>
        <tbody>{error ? <tr><td colSpan={7}><div className="table-message error-text" role="alert">{error}</div></td></tr> : loading ? <tr><td colSpan={7}><div className="table-message" role="status">Loading packets…</div></td></tr> : items.length ? items.map(packet => <tr key={packet.id}>
          <td className="mono packet-id">{String(packet.id).padStart(4, '0')}</td><td className="mono">{time(packet.timestamp)}</td>
          <td className="mono">{packet.bssid || packet.source_mac || '—'}</td><td className="ssid-cell" title={packet.ssid || ''}>{packet.ssid || '—'}</td><td className="mono">{packet.rssi_dbm != null ? `${packet.rssi_dbm} dBm` : '—'}</td>
          <td><span className={packet.prediction ? 'detection-positive' : 'muted'}>{packet.prediction ? (packet.attack_type === 'suspected_rogue_ap' ? 'Rogue-AP activity' : 'Suspected evil twin') : packet.evaluated === false ? 'Context only' : 'No detection'}</span>{packet.evasion_tags.length > 0 && <div className="packet-tags" title={packet.evasion_tags.join(', ')}>{packet.evasion_tags.join(' · ')}</div>}</td>
          <td><span className={`badge ${packet.severity}`}>{packet.severity}</span></td>
        </tr>) : <tr><td colSpan={7}><div className="table-message">{!capture ? 'Upload a PCAP or AWID CSV to inspect its packets.' : 'No packets match these filters.'}{capture && filtered && <button className="text-button" onClick={() => onFilters({ mac: '', attack_type: '', severity: '' })}>Clear filters</button>}</div></td></tr>}</tbody>
      </table>
    </div>
    <div className="table-footer"><span aria-live="polite">{!loading && total ? `${count((page - 1) * 8 + 1)}–${count(Math.min(page * 8, total))} of ${count(total)} packets` : loading ? 'Updating results…' : '0 packets'}</span>
      <div className="pagination"><button aria-label="Previous page" disabled={page <= 1 || loading} onClick={() => setPage(page - 1)}><ChevronLeft size={15} /></button><span>Page {page} of {Math.max(1, result?.pages || 1)}</span><button aria-label="Next page" disabled={!total || page >= (result?.pages || 1) || loading} onClick={() => setPage(page + 1)}><ChevronRight size={15} /></button></div>
    </div>
  </section>;
}
