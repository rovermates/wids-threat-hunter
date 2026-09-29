import { useState } from 'react';
import { Info } from 'lucide-react';
import { count, percent } from '../api';

const featureLabel = value => value.replace('missingindicator_', 'Missing: ').replaceAll('_', ' ');

export default function ModelPerformance({ model }) {
  const [all, setAll] = useState(false);
  const benchmark = model?.benchmark;
  const features = model?.feature_importance || [];
  const visible = all ? features : features.slice(0, 5);
  const max = features[0]?.importance || 1;
  const matrix = benchmark?.confusion_matrix;
  return <section className="panel model-panel" aria-labelledby="model-heading">
    <div className="panel-heading"><div><h2 id="model-heading">Model insights</h2><p>{model?.model_name || 'Detection model'}</p><p>{model?.target}</p></div><span className="quiet-badge">Research model</span></div>
    <div className="model-grid"><div className="importance-panel"><div className="row-between"><h3>Feature importance</h3><span className="subtle-label" title={model?.importance_method}>{model?.importance_method?.includes('permutation') ? 'Validation permutation' : 'Tree contribution'}</span></div>
      {visible.length ? <div className="importance-bars">{visible.map(item => <div className="importance-row" key={item.feature}>
        <div className="row-between"><span title={item.feature}>{featureLabel(item.feature)}</span><span className="mono">{percent(item.importance)}</span></div>
        <div className="bar-track" role="meter" aria-label={featureLabel(item.feature)} aria-valuemin={0} aria-valuemax={100} aria-valuenow={item.importance * 100}><span style={{ width: `${item.importance / max * 100}%` }} /></div>
      </div>)}</div> : <p className="insight-empty">Feature importance is unavailable. Check the model setup.</p>}
      {features.length > 5 && <button className="text-button feature-toggle" onClick={() => setAll(!all)}>{all ? 'Show top 5' : `View all ${features.length} features`}</button>}
    </div><div className="matrix-panel"><h3>Confusion matrix</h3><p className="matrix-caption">Actual ↓ &nbsp; Predicted →</p>
      {matrix ? <><div className="matrix-grid" role="table" aria-label="Benchmark confusion matrix">
        <div role="row" className="matrix-row matrix-labels"><span role="columnheader" /><span role="columnheader">Non-target</span><span role="columnheader">{benchmark.labels?.[1] || 'Evil twin'}</span></div>
        <div role="row" className="matrix-row"><span role="rowheader" className="matrix-side">Non-target</span><div role="cell" className="matrix-cell correct"><strong>{count(matrix[0][0])}</strong><span>True negative</span></div><div role="cell" className="matrix-cell incorrect"><strong>{count(matrix[0][1])}</strong><span>False positive</span></div></div>
        <div role="row" className="matrix-row"><span role="rowheader" className="matrix-side">{benchmark.labels?.[1] || 'Evil twin'}</span><div role="cell" className="matrix-cell incorrect"><strong>{count(matrix[1][0])}</strong><span>False negative</span></div><div role="cell" className="matrix-cell correct"><strong>{count(matrix[1][1])}</strong><span>True positive</span></div></div>
      </div><div className="matrix-metrics"><span>Precision <strong>{percent(benchmark.precision)}</strong></span><span>Recall <strong>{percent(benchmark.recall)}</strong></span></div></> : <p className="insight-empty">{model?.benchmark_note || 'No verified benchmark is available.'}</p>}
    </div></div>
    {model?.additional_benchmark && <p className="matrix-caption">{model.additional_benchmark.source}: F1 {percent(model.additional_benchmark.f1)}. Same capture and devices; not independent-device testing.</p>}
    {model?.regression_benchmarks?.length > 0 && <details className="model-regressions"><summary>Additional detection checks</summary>
      {model.regression_benchmarks.map(item => <p className="matrix-caption" key={item.source}>
        {item.source}: {item.positive_rows > 0 ? `precision ${percent(item.precision)}, recall ${percent(item.recall)}, F1 ${percent(item.f1)}. ` : ''}
        {count(item.false_positives)} false alerts / {count(item.negative_rows)} non-target advertisements; {count(item.false_negatives)} missed / {count(item.positive_rows)} target advertisements.
      </p>)}<p className="matrix-caption">Previously inspected captures; these checks do not establish accuracy on unseen networks.</p>
    </details>}
    <div className="model-note"><Info size={14} /><span>{benchmark ? `${benchmark.source} · ${count(benchmark.rows)} ${benchmark.scope === 'ap_advertisements' ? 'AP advertisements' : 'frames'}. ${benchmark.note} These metrics do not measure your uploaded capture.` : model?.error || 'Benchmark metrics require a matching model artifact.'}</span></div>
  </section>;
}
