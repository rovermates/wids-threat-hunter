import { useEffect, useState } from 'react';
import { Download, FileJson, FileSpreadsheet, Shield } from 'lucide-react';
import { downloadBlob, exportPackets, query, request } from '../api';

export default function ThreatMitigation({ capture, filters }) {
  const [options, setOptions] = useState({ iptables: false, hostapd: false });
  const [rules, setRules] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [exporting, setExporting] = useState(null);
  useEffect(() => {
    setRules(null);
    setError(null);
    if (!capture || (!options.iptables && !options.hostapd)) { setBusy(false); return; }
    const controller = new AbortController();
    setBusy(true);
    request(`/rules?${query({ analysis_id: capture.id, ...options })}`, { signal: controller.signal })
      .then(data => { setRules(data); setBusy(false); })
      .catch(err => { if (err.name !== 'AbortError') { setError(err.message); setBusy(false); } });
    return () => controller.abort();
  }, [capture?.id, options.iptables, options.hostapd]);
  async function exportFile(format) {
    setError(null);
    setExporting(format);
    try { await exportPackets({ analysis_id: capture.id, format, ...filters }); }
    catch (err) { setError(err.message); }
    finally { setExporting(null); }
  }
  return <section className="panel mitigation-panel" aria-labelledby="mitigation-heading">
    <div className="panel-heading"><div><h2 id="mitigation-heading">Threat mitigation</h2><p>Prepare rules for manual review</p></div><Shield size={18} className="muted" /></div>
    <div className="mitigation-body">
      {[['iptables', 'iptables rules', 'Routed IP source-MAC filter'], ['hostapd', 'hostapd deny list', 'Client association restriction']].map(([key, title, description]) => <div className="toggle-row" key={key}>
        <div><h3 id={`${key}-label`}>{title}</h3><p>{description}</p></div><button role="switch" aria-checked={options[key]} aria-labelledby={`${key}-label`} className={`toggle ${options[key] ? 'on' : ''}`} disabled={!capture} onClick={() => setOptions({ ...options, [key]: !options[key] })}><span /></button>
      </div>)}
      <p className="rule-note">Templates only. These rules do not suppress rogue AP beacons or execute automatically.</p>
      {busy && <p className="subtle-label" role="status">Preparing templates…</p>}
      {rules && <div className="rule-results"><p>{rules.targets} detected BSSID{rules.targets === 1 ? '' : 's'} · review before use</p>{rules.files.map(file => <details key={file.name}><summary>{file.name}</summary><pre>{file.content}</pre><button className="text-button" disabled={!rules.targets || rules.analysis_id !== capture?.id} onClick={() => downloadBlob(new Blob([file.content], { type: 'text/plain' }), file.name)}><Download size={13} />Download template</button></details>)}</div>}
      <div className="export-section"><h3>Export packet results</h3><p>All packets matching the table filters</p><div className="export-actions">
        <button className="button secondary" disabled={!capture || !!exporting} onClick={() => exportFile('json')}><FileJson size={15} />{exporting === 'json' ? 'Exporting…' : 'JSON'}<Download size={13} /></button>
        <button className="button secondary" disabled={!capture || !!exporting} onClick={() => exportFile('csv')}><FileSpreadsheet size={15} />{exporting === 'csv' ? 'Exporting…' : 'CSV'}<Download size={13} /></button>
      </div></div>
      {error && <p className="error-text inline-error" role="alert">{error}</p>}
    </div>
  </section>;
}
