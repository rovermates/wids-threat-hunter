import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { AlertCircle, ArrowUpRight, CheckCircle2, FileUp, LoaderCircle, Radio, Upload, X } from 'lucide-react';
import { count, request } from './api';
import DashboardOverview from './components/DashboardOverview';
import ThreatFeed from './components/ThreatFeed';
import PacketAnalyzerTable from './components/PacketAnalyzerTable';
import ModelPerformance from './components/ModelPerformance';
import ThreatMitigation from './components/ThreatMitigation';

const emptyFilters = { mac: '', attack_type: '', severity: '' };
const TrafficChart = lazy(() => import('./components/TrafficChart'));
const pending = job => job && ['accepted', 'receiving', 'queued', 'processing'].includes(job.status);

export default function App() {
  const [snapshot, setSnapshot] = useState(null);
  const [health, setHealth] = useState(null);
  const [connectionError, setConnectionError] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [job, setJob] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [variant, setVariant] = useState('CLS');
  const [filters, setFilters] = useState(emptyFilters);
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const input = useRef(null);
  const lastId = useRef(undefined);
  const capture = snapshot?.metrics.capture;
  const model = snapshot?.metrics.model;
  const working = submitting || pending(job);
  const enabled = health?.model_ready && !working && !connectionError;

  useEffect(() => {
    let cancelled = false;
    let timer;
    const controller = new AbortController();
    async function poll() {
      try {
        const [metrics, status] = await Promise.all([request('/metrics', { signal: controller.signal }), request('/health', { signal: controller.signal })]);
        const id = metrics.capture?.id ?? null;
        const feed = await request(`/threats${id ? `?analysis_id=${id}` : ''}`, { signal: controller.signal });
        let traffic;
        if (lastId.current !== id) traffic = await request(`/traffic${id ? `?analysis_id=${id}` : ''}`, { signal: controller.signal });
        if (cancelled) return;
        if (lastId.current !== id) { setPage(1); lastId.current = id; }
        setSnapshot(previous => ({ metrics, feed, traffic: traffic || previous?.traffic }));
        setHealth(status);
        if (status.active_job) setJob(current => current?.id === status.active_job.id ? current : status.active_job);
        setConnectionError(null);
      } catch (err) {
        if (!cancelled && err.name !== 'AbortError') setConnectionError(err.status === 409 ? 'Capture changed. Refreshing results…' : 'Cannot reach the API. Check that the backend is running.');
      } finally {
        if (!cancelled) timer = setTimeout(poll, 5000);
      }
    }
    poll();
    return () => { cancelled = true; controller.abort(); clearTimeout(timer); };
  }, [refresh]);

  useEffect(() => {
    if (!pending(job)) return;
    let cancelled = false;
    let timer;
    const controller = new AbortController();
    async function pollJob() {
      try {
        const result = await request(`/jobs/${job.id}`, { signal: controller.signal });
        if (cancelled) return;
        setJob(result);
        if (result.status === 'completed') setRefresh(value => value + 1);
        else if (result.status === 'failed') setActionError(result.error);
        else timer = setTimeout(pollJob, 1000);
      } catch (err) {
        if (cancelled || err.name === 'AbortError') return;
        setActionError(err.message);
        if (err.status === 404) { setJob(null); setRefresh(value => value + 1); }
        else timer = setTimeout(pollJob, 2000);
      }
    }
    pollJob();
    return () => { cancelled = true; controller.abort(); clearTimeout(timer); };
  }, [job?.id, Boolean(pending(job))]);

  function updateFilters(next) { setFilters(next); setPage(1); }

  async function analyze(file = null) {
    setActionError(null);
    if (file && !/\.(csv|pcap|pcapng)$/i.test(file.name)) { setActionError('Choose a .pcap, .pcapng, or AWID .csv file.'); return; }
    if (file && file.size > health.max_upload_bytes) { setActionError(`This file exceeds the ${health.max_upload_bytes / 1024 / 1024} MB limit. Split the capture and retry.`); return; }
    setSubmitting(true);
    try {
      let result;
      if (file) {
        const body = new FormData();
        body.append('file', file);
        if (/\.csv$/i.test(file.name)) body.append('variant', file.name.match(/AWID-(CLS|ATK)-R-/i)?.[1].toUpperCase() || variant);
        result = await request('/upload', { method: 'POST', body });
      } else result = await request('/sample', { method: 'POST' });
      setJob({ ...result, filename: file?.name || 'sample_awid.csv', processed_packets: 0 });
    } catch (err) { setActionError(err.message); }
    finally { setSubmitting(false); if (input.current) input.current.value = ''; }
  }

  return <>
    <a className="skip-link" href="#main">Skip to dashboard</a>
    <header className="site-header"><div className="header-inner"><a href="/" className="brand" aria-label="WIDS Threat Hunter home"><span className="brand-icon"><Radio size={20} strokeWidth={1.8} /></span><strong>WIDS<span>Threat Hunter</span></strong></a><div className="header-context"><span className="header-divider" />Wireless security dashboard</div><div className="connection"><span className={`status-dot ${connectionError ? 'offline' : !health ? 'connecting' : ''}`} />{connectionError ? 'API offline' : health ? 'Local workspace' : 'Connecting…'}</div></div></header>
    <main id="main" className="dashboard">
      <div className="page-heading"><div><div className="eyebrow">CAPTURE ANALYSIS</div><h1>Threat overview</h1><p>A clear view of your wireless traffic.</p></div>
        <div className="upload-controls"><button className="button secondary" onClick={() => analyze()} disabled={!enabled}><FileUp size={16} />Load sample</button><button className="button primary" onClick={() => input.current.click()} disabled={!enabled}>{working ? <LoaderCircle className="spin" size={16} /> : <Upload size={16} />}{working ? 'Analyzing…' : 'Upload capture'}</button><input ref={input} type="file" className="sr-only" tabIndex={-1} aria-label="Upload capture file" accept=".pcap,.pcapng,.csv" onChange={event => event.target.files[0] && analyze(event.target.files[0])} /></div>
      </div>
      <div className="capture-toolbar"><div className="capture-source"><span className={`capture-mark ${capture ? 'loaded' : ''}`} /><span title={capture?.filename}>{capture?.filename || 'No capture selected'}</span>{capture && <span className="quiet-badge">{capture.format}</span>}</div><div className="upload-help"><span>PCAP / AWID CSV · {health ? health.max_upload_bytes / 1024 / 1024 : 64} MB max</span><label>CSV labels <select aria-label="CSV label variant" value={variant} disabled={working} onChange={event => setVariant(event.target.value)}><option value="CLS">CLS</option><option value="ATK">ATK</option></select></label></div></div>
      {connectionError && <div className="notice error" role="alert"><AlertCircle size={17} /><span>{connectionError}</span><button className="text-button" onClick={() => setRefresh(value => value + 1)}>Retry</button></div>}
      {model && !model.ready && <div className="notice error" role="alert"><AlertCircle size={17} /><span>{model.error}</span></div>}
      {health && !health.pcap_available && <div className="notice"><AlertCircle size={17} /><span>PCAP processing needs tshark 4.4+. Install it or set TSHARK_PATH. AWID CSV analysis is available.</span></div>}
      {actionError && <div className="notice error" role="alert"><AlertCircle size={17} /><span>{actionError}</span><button className="icon-button" aria-label="Dismiss error" onClick={() => setActionError(null)}><X size={16} /></button></div>}
      {(working || job?.status === 'completed') && <div className={`notice ${working ? '' : 'success'}`} role="status">{working ? <LoaderCircle size={16} className="spin" /> : <CheckCircle2 size={16} />}<span>{submitting ? 'Uploading capture…' : working ? `Processing ${job.filename} · ${count(job.processed_packets)} packets analyzed. Previous results remain visible.` : `Analysis complete · ${count(job.processed_packets)} packets processed.`}</span>{!working && <button className="icon-button" aria-label="Dismiss status" onClick={() => setJob(null)}><X size={16} /></button>}</div>}
      {!snapshot && !connectionError && <p className="loading-label" role="status">Loading dashboard…</p>}
      <DashboardOverview capture={capture} benchmark={model?.benchmark} />
      {snapshot?.metrics.needs_reanalysis && <div className="notice" role="status"><AlertCircle size={17} /><span>Saved capture results use an earlier model. Re-upload the capture to analyze it with the current detector.</span></div>}
      {model?.scope === 'ap_advertisements' && <p className="loading-label">Detection covers AP beacons and probe responses. Other frames provide context; no alert does not establish that a network is safe.</p>}
      <div className="dashboard-grid"><Suspense fallback={<section className="panel empty-state chart-empty" role="status">Loading traffic chart…</section>}><TrafficChart traffic={snapshot?.traffic} capture={capture} /></Suspense><ThreatFeed feed={snapshot?.feed} capture={capture} onInspect={mac => { updateFilters({ ...emptyFilters, mac }); document.getElementById('packets').scrollIntoView({ block: 'start' }); }} /></div>
      <PacketAnalyzerTable capture={capture} filters={filters} onFilters={updateFilters} page={page} setPage={setPage} />
      <div className="dashboard-grid bottom-grid"><ModelPerformance model={model} /><ThreatMitigation capture={capture} filters={filters} /></div>
      <footer className="page-footer"><span>WIDS Threat Hunter <span className="footer-dot">·</span> Offline capture analysis</span><a href="/docs" target="_blank" rel="noreferrer">API documentation <ArrowUpRight size={13} /></a></footer>
    </main>
  </>;
}
