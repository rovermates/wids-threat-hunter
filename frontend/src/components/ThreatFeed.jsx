import { ArrowUpRight, Radar, ShieldCheck } from 'lucide-react';
import { count, time } from '../api';

export default function ThreatFeed({ feed, capture, onInspect }) {
  const items = feed?.items || [];
  return <section className="panel threat-panel" aria-labelledby="threat-heading">
    <div className="panel-heading"><div><h2 id="threat-heading">Threat feed <span className="count-badge">{count(feed?.total || 0)}</span></h2><p>Suspected rogue access points</p></div><Radar size={18} className="muted" /></div>
    {items.length ? <div className="threat-list">{items.map(item => <article className="threat-item" key={item.bssid}>
      <div className="row-between"><strong className="truncate" title={item.ssid || 'Unknown SSID'}>{item.ssid || 'Unknown SSID'}</strong><span className={`badge ${item.severity}`}>{item.severity}</span></div>
      <button className="address-link" onClick={() => onInspect(item.bssid)} title="Filter packet table by this BSSID">{item.bssid}<ArrowUpRight size={13} /></button>
      <div className="tag-list">{item.evasion_tags.length ? item.evasion_tags.map(tag => <span key={tag}>{tag}</span>) : <span>Model detection</span>}</div>
      <div className="threat-meta"><span>{count(item.packets)} flagged frames</span><time dateTime={item.last_seen}>{time(item.last_seen)} UTC</time></div>
    </article>)}</div> : <div className="empty-state threat-empty"><span className="empty-icon"><ShieldCheck size={25} strokeWidth={1.5} /></span>
      <h3>{capture ? 'No rogue APs identified' : 'Ready for your first capture'}</h3><p>{capture ? 'No attributable model detections in this capture. This does not guarantee the network is safe.' : 'Detected BSSIDs and their evidence will appear here.'}</p></div>}
    <div className="panel-footnote">Evidence tags are heuristics · refreshes every 5s{feed?.total > items.length && <p>Showing {count(items.length)} of {count(feed.total)} APs. Export packets for the full results.</p>}{capture?.unattributed_positive_packets > 0 && <p>{count(capture.unattributed_positive_packets)} positive frames lack attributable AP advertising evidence.</p>}</div>
  </section>;
}
