#!/usr/bin/env python3
import json, urllib.request, datetime

ASSET = "SPYX"
RES = "minute"          # finest grain we pull
BUCKET_MIN = 15         # aggregate into 15-minute candles

# Fetch today's minute data
url = ("https://pricedb.crunchdao.com/v1/prices"
       f"?asset={ASSET}&resolution={RES}"
       "&from=2026-06-23T00:00:00&to=2026-06-23T23:59:59")
with urllib.request.urlopen(url) as r:
    data = json.load(r)

ts = data["timestamp"]
cls = data["close"]

# Bucket into candles of BUCKET_MIN minutes
epoch = ts[0] - (ts[0] % (BUCKET_MIN * 60))
buckets = {}
for t, c in zip(ts, cls):
    b = t - (t % (BUCKET_MIN * 60))
    buckets.setdefault(b, []).append(c)

candles = []
for b in sorted(buckets):
    vals = buckets[b]
    candles.append({
        "time": b,
        "open": vals[0],
        "high": max(vals),
        "low": min(vals),
        "close": vals[-1],
    })

# Build a self-contained HTML file using TradingView lightweight-charts (CDN)
rows = ",\n".join(
    f'{{ time: {c["time"]}, open: {c["open"]}, high: {c["high"]}, low: {c["low"]}, close: {c["close"]} }}'
    for c in candles
)

html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>{ASSET} {BUCKET_MIN}-min Candles</title>
<script src="https://unpkg.com/lightweight-charts/dist/lightweight-charts.standalone.production.js"></script>
</head><body style="margin:0;background:#0e1116">
<div id="chart" style="width:100vw;height:100vh"></div>
<script>
const chart = LightweightCharts.createChart(document.getElementById('chart'), {{
  layout: {{ background: {{ color: '#0e1116' }}, textColor: '#d1d4dc' }},
  grid: {{ vertLines: {{ color: '#1c2230' }}, horzLines: {{ color: '#1c2230' }} }},
  timeScale: {{ timeVisible: true, secondsVisible: false, borderColor: '#363a45' }},
  rightPriceScale: {{ borderColor: '#363a45' }},
  crosshair: {{ mode: LightweightCharts.CrosshairMode.Normal }},
}});
const series = chart.addCandlestickSeries({{
  upColor: '#26a69a', downColor: '#ef5350',
  borderUpColor: '#26a69a', borderDownColor: '#ef5350',
  wickUpColor: '#26a69a', wickDownColor: '#ef5350',
}});
series.setData([
{rows}
]);
chart.timeScale().fitContent();
</script>
</body></html>
"""

out = "spyx_candles.html"
with open(out, "w") as f:
    f.write(html)

# Also print a compact summary
import statistics
print(f"{ASSET} — {BUCKET_MIN}-min candles for 2026-06-23")
print(f"Candles: {len(candles)}")
opens = [c["open"] for c in candles]
print(f"Session open: {opens[0]:.2f}")
print(f"Session close: {candles[-1]['close']:.2f}")
print(f"Change: {candles[-1]['close']-opens[0]:+.2f} ({(candles[-1]['close']/opens[0]-1)*100:+.2f}%)")
print(f"Day high: {max(c['high'] for c in candles):.2f}")
print(f"Day low:  {min(c['low'] for c in candles):.2f}")
print(f"\nChart written to {out}")
