import { useState } from 'react';
import { Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Activity } from 'lucide-react';
import { time } from '../api';

export default function TrafficChart({ traffic, capture }) {
  const [rssi, setRssi] = useState(true);
  const [rate, setRate] = useState(true);
  const data = traffic?.items || [];
  const variances = data.filter(item => item.rssi_variance != null).map(item => item.rssi_variance);
  return <section className="panel traffic-panel" aria-labelledby="traffic-heading">
    <div className="panel-heading"><div><h2 id="traffic-heading">Traffic anomalies</h2><p>Signal variation and frame activity over capture time</p></div>
      <span className="subtle-label">UTC</span></div>
    <div className="chart-legend">
      <label><input type="checkbox" checked={rssi} onChange={e => setRssi(e.target.checked)} /><i className="legend-line blue" />RSSI variance <span>dB²</span></label>
      <label><input type="checkbox" checked={rate} onChange={e => setRate(e.target.checked)} /><i className="legend-line teal" />Frame rate <span>fps</span></label>
    </div>
    {data.length ? <>
      <div className="traffic-chart" aria-label="Time-series chart of RSSI variance and frame rate">
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <ComposedChart data={data} margin={{ top: 14, right: 0, left: -24, bottom: 4 }} accessibilityLayer>
            <CartesianGrid stroke="#e9edf3" strokeDasharray="3 4" vertical={false} />
            <XAxis dataKey="timestamp" tickFormatter={time} axisLine={false} tickLine={false} minTickGap={40} tick={{ fontSize: 11, fill: '#69778d' }} dy={8} />
            <YAxis yAxisId="rssi" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#69778d' }} width={55} />
            <YAxis yAxisId="rate" orientation="right" axisLine={false} tickLine={false} tick={{ fontSize: 11, fill: '#69778d' }} width={42} />
            <Tooltip labelFormatter={value => `${time(value)} UTC`} formatter={(value, name) => [Number(value).toFixed(2), name]} contentStyle={{ border: '1px solid #e0e6ef', borderRadius: 8, fontSize: 12 }} />
            {rssi && <Area yAxisId="rssi" type="monotone" dataKey="rssi_variance" name="RSSI variance (dB²)" stroke="#2c5fe8" fill="#2c5fe8" fillOpacity={.055} strokeWidth={2} connectNulls={false} isAnimationActive={false} dot={data.length < 3} />}
            {rate && <Line yAxisId="rate" type="linear" dataKey="frame_rate" name="Frame rate (fps)" stroke="#23877e" strokeWidth={1.8} dot={data.length < 3} isAnimationActive={false} />}
          </ComposedChart>
        </ResponsiveContainer>
      </div>
      <div className="chart-footnote"><span>{traffic.bin_seconds}s bins · mean within-AP RSSI variance</span><span>{variances.length ? `Peak ${Math.max(...variances).toFixed(1)} dB²` : 'RSSI unavailable in capture'}</span></div>
    </> : <div className="empty-state chart-empty"><Activity size={27} strokeWidth={1.4} /><h3>No traffic to chart yet</h3><p>{capture ? 'Traffic data is unavailable. Refresh to retry.' : 'Upload a capture or load the sample to see real packet activity.'}</p></div>}
  </section>;
}
