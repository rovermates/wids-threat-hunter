import { Activity, Radio, ShieldCheck, Target } from 'lucide-react';
import { count, percent } from '../api';

export default function DashboardOverview({ capture, benchmark }) {
  const level = capture?.threat_level;
  return <section className="kpi-strip" aria-label="Capture overview">
    <div className="kpi"><div className="kpi-label"><Activity size={16} />Analyzed packets</div>
      <div className="kpi-value">{count(capture?.total_packets)}</div>
      <p>{capture ? (capture.scope === 'ap_advertisements' ? `${count(capture.evaluated_packets)} AP advertisements evaluated` : '802.11 frames in this capture') : 'Upload a capture to begin'}</p></div>
    <div className="kpi"><div className="kpi-label"><Radio size={16} />Detected rogue APs</div>
      <div className="kpi-value">{count(capture?.detected_rogue_aps)}<span className="kpi-unit">suspected</span></div>
      <p>{capture ? `${count(capture.flagged_packets)} flagged packets` : 'Unique flagged BSSIDs'}</p></div>
    <div className="kpi"><div className="kpi-label"><Target size={16} />Accuracy / F1 score</div>
      <div className="kpi-value performance-value">{percent(benchmark?.accuracy)}<span className="kpi-divider">/</span><span>{percent(benchmark?.f1)}</span></div>
      <p>{benchmark?.scope === 'ap_advertisements' ? 'AP advertisements · diagnostic benchmark' : benchmark?.source || 'Benchmark unavailable'}</p></div>
    <div className="kpi"><div className="kpi-label"><ShieldCheck size={16} />Current threat level</div>
      <div className={`kpi-value level-value ${level || 'unknown'}`}><span className="status-dot" />{level ? level[0].toUpperCase() + level.slice(1) : 'Awaiting data'}</div>
      <p>{!capture ? 'No capture analyzed' : level === 'unknown' ? 'No eligible AP advertisements captured' : level === 'low' ? 'No model detections in evaluated frames' : 'Review the flagged traffic'}</p></div>
  </section>;
}
