const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT) || 5000;

app.use(cors());
app.use(express.json({ limit: "25mb" }));
app.use(express.static(path.join(__dirname, "public")));

const DEFAULTS = {
  learnPct: 50, window: 10,
  bytesMult: 5, minBytes: 1_000_000,
  ports: 20, destMult: 3, minDest: 15,
  dnsMult: 5, minDns: 50, failMult: 5, minFail: 10,
  sweepHosts: 10, spreadHosts: 3
};

const privateIPv4 = (ip) =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(String(ip || ""));
const isFailed = (status) => /den|drop|block|fail|reject|reset|timeout/i.test(String(status || ""));
const isDns = (r) => Number(r.dp) === 53 || Boolean(r.dn);
const meanStd = (values) => {
  if (!values.length) return { mean: 0, std: 0 };
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
  return { mean, std: Math.sqrt(variance) };
};
const formatBytes = (n) => n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB`
  : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB`
  : n >= 1e3 ? `${(n / 1e3).toFixed(1)} KB` : `${Math.round(n)} B`;

function normalizeRecord(row, index) {
  const ts = typeof row.ts === "number" ? row.ts : Date.parse(row.ts);
  const src = String(row.src || "").trim();
  const dst = String(row.dst || "").trim();
  const b = Number(row.b ?? 0);
  const dp = row.dp === null || row.dp === "" || row.dp === undefined ? null : Number(row.dp);
  if (!src || !dst) throw new Error(`Record ${index + 1}: source and destination IP are required.`);
  if (!Number.isFinite(ts)) throw new Error(`Record ${index + 1}: invalid timestamp.`);
  if (!Number.isFinite(b) || b < 0) throw new Error(`Record ${index + 1}: bytes must be a non-negative number.`);
  if (dp !== null && (!Number.isInteger(dp) || dp < 0 || dp > 65535)) {
    throw new Error(`Record ${index + 1}: destination port must be between 0 and 65535.`);
  }
  return { ts, src, dst, dp, pr: String(row.pr || "?"), b, st: String(row.st || ""), dn: String(row.dn || "") };
}

function analyzeRecords(input, suppliedConfig = {}) {
  const c = { ...DEFAULTS, ...suppliedConfig };
  c.learnPct = Math.max(10, Math.min(90, Number(c.learnPct) || 50));
  c.window = Math.max(1, Number(c.window) || 10);
  const rows = input.map(normalizeRecord).sort((a, b) => a.ts - b.ts);
  if (rows.length < 2) throw new Error("At least two valid records are required.");
  const start = rows[0].ts;
  const end = rows[rows.length - 1].ts;
  const split = start + (end - start) * c.learnPct / 100;
  const windowMs = c.window * 60_000;
  const learning = rows.filter(r => r.ts < split);
  const evaluation = rows.filter(r => r.ts >= split);
  if (learning.length < 5 || evaluation.length < 1) {
    throw new Error("Not enough records in the learning and evaluation periods. Use a larger dataset or change the learning percentage.");
  }

  const bucketsFor = (list, duration) => {
    const result = new Map();
    for (const r of list) {
      const key = `${r.src}|${Math.floor(r.ts / duration)}`;
      if (!result.has(key)) result.set(key, { host: r.src, bucket: Math.floor(r.ts / duration), bytes: 0, records: 0, dst: new Set(), ports: new Set(), dns: 0, failed: 0, internalByPort: new Map() });
      const b = result.get(key);
      b.bytes += r.b; b.records += 1; b.dst.add(r.dst);
      if (r.dp !== null) b.ports.add(r.dp);
      if (isDns(r)) b.dns += 1;
      if (isFailed(r.st)) b.failed += 1;
      if (r.dp !== null && privateIPv4(r.dst)) {
        if (!b.internalByPort.has(r.dp)) b.internalByPort.set(r.dp, new Set());
        b.internalByPort.get(r.dp).add(r.dst);
      }
    }
    return result;
  };

  const learnBuckets = bucketsFor(learning, windowMs);
  const learnMinuteBuckets = bucketsFor(learning, 60_000);
  const evalBuckets = bucketsFor(evaluation, windowMs);
  const evalMinuteBuckets = bucketsFor(evaluation, 60_000);
  const baseline = new Map();
  const learningPairs = new Set(learning.map(r => `${r.src}>${r.dst}`));
  const learningRowsByHost = new Map();

  for (const r of learning) {
    if (!learningRowsByHost.has(r.src)) learningRowsByHost.set(r.src, []);
    learningRowsByHost.get(r.src).push(r);
  }

  for (const host of new Set([...learnBuckets.values()].map(b => b.host))) {
    const bs = [...learnBuckets.values()].filter(b => b.host === host);
    const mins = [...learnMinuteBuckets.values()].filter(b => b.host === host);
    baseline.set(host, {
      bytes: meanStd(bs.map(b => b.bytes)),
      destinations: meanStd(bs.map(b => b.dst.size)),
      dns: meanStd(bs.map(b => b.dns)),
      failed: meanStd(bs.map(b => b.failed)),
      maxPortsPerMinute: Math.max(0, ...mins.map(b => b.ports.size)),
      knownDestinations: new Set((learningRowsByHost.get(host) || []).map(r => r.dst))
    });
  }

  const findings = [];
  const add = (host, rule, observed, baselineText, recommendation, bucketStart, severity = "Medium") => {
    findings.push({ host, rule, observed, baseline: baselineText, recommendation, timestamp: new Date(bucketStart).toISOString(), severity });
  };

  for (const b of evalBuckets.values()) {
    const base = baseline.get(b.host) || { bytes: { mean: 0, std: 0 }, destinations: { mean: 0, std: 0 }, dns: { mean: 0, std: 0 }, failed: { mean: 0, std: 0 }, maxPortsPerMinute: 0, knownDestinations: new Set() };
    const at = b.bucket * windowMs;
    const byteThreshold = Math.max(base.bytes.mean + 3 * base.bytes.std, base.bytes.mean * c.bytesMult, c.minBytes);
    if (b.bytes > byteThreshold) add(b.host, "Unusual data transfer", `${formatBytes(b.bytes)} in ${c.window} min`, `mean ${formatBytes(base.bytes.mean)}; threshold ${formatBytes(byteThreshold)}`, "Check destination ownership, backup jobs, and bytes per flow.", at, "High");

    const destThreshold = Math.max(c.minDest, base.destinations.mean * c.destMult);
    if (b.dst.size > destThreshold) add(b.host, "Destination diversity", `${b.dst.size} distinct destinations`, `mean ${base.destinations.mean.toFixed(1)}; threshold ${destThreshold.toFixed(0)}`, "Review the destination list and verify whether discovery or scanning is expected.", at, "High");

    const dnsThreshold = Math.max(c.minDns, base.dns.mean * c.dnsMult);
    if (b.dns > dnsThreshold) add(b.host, "DNS behaviour", `${b.dns} DNS flows`, `mean ${base.dns.mean.toFixed(1)}; threshold ${dnsThreshold.toFixed(0)}`, "Inspect queried domains and the resolver used.", at, "Medium");

    const failThreshold = Math.max(c.minFail, base.failed.mean * c.failMult);
    if (b.failed > failThreshold) add(b.host, "Blocked/failed connections", `${b.failed} failures`, `mean ${base.failed.mean.toFixed(1)}; threshold ${failThreshold.toFixed(0)}`, "Check firewall logs, target ports, and client configuration.", at, "Medium");

    const newPeers = [...b.dst].filter(dst => privateIPv4(dst) && !learningPairs.has(`${b.host}>${dst}`));
    if (newPeers.length && base.knownDestinations.size >= 3) {
      add(b.host, "Unexpected host communication", `${newPeers.length} new internal peer(s): ${newPeers.slice(0, 5).join(", ")}`, `${base.knownDestinations.size} known destinations during learning`, "Ask the host owner whether these internal connections are expected.", at, "Medium");
    }

    for (const [port, targets] of b.internalByPort) {
      if (targets.size >= c.sweepHosts && targets.size > base.destinations.mean * c.destMult) {
        add(b.host, "Network sweep", `${targets.size} internal hosts on port ${port}`, `threshold ${c.sweepHosts} hosts per ${c.window}-minute window`, "Confirm whether this source is an approved scanner; otherwise investigate the source and responding hosts.", at, "Critical");
      }
    }
  }

  for (const b of evalMinuteBuckets.values()) {
    const base = baseline.get(b.host);
    const maxPorts = base ? base.maxPortsPerMinute : 0;
    if (b.ports.size > c.ports && b.ports.size > maxPorts) {
      add(b.host, "Port probing", `${b.ports.size} distinct destination ports in one minute`, `learning maximum ${maxPorts}; configured threshold ${c.ports}`, "Inspect the ports touched and confirm whether an approved inventory scanner ran.", b.bucket * 60_000, "High");
    }
  }

  const spreadBuckets = new Map();
  for (const r of evaluation) {
    if (r.dp === null || ![22, 135, 445, 3389, 5985].includes(r.dp) || !privateIPv4(r.dst) || isFailed(r.st)) continue;
    if (learningPairs.has(`${r.src}>${r.dst}`)) continue;
    const k = `${r.src}|${Math.floor(r.ts / windowMs)}`;
    if (!spreadBuckets.has(k)) spreadBuckets.set(k, { host: r.src, targets: new Set(), start: r.ts });
    spreadBuckets.get(k).targets.add(r.dst);
  }
  for (const b of spreadBuckets.values()) {
    if (b.targets.size >= c.spreadHosts) {
      add(b.host, "Lateral spreading", `${b.targets.size} new internal admin-port targets`, `no prior admin-port path in learning data`, "Review authentication logs and deployment activity; isolate only if corroborating evidence supports it.", b.start, "Critical");
    }
  }

  findings.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const unique = new Map();
  for (const f of findings) {
    const key = `${f.host}|${f.rule}|${f.timestamp}|${f.observed}`;
    if (!unique.has(key)) unique.set(key, f);
  }
  const anomalies = [...unique.values()];
  const hosts = new Set(rows.flatMap(r => [r.src, r.dst]));
  return {
    recordsProcessed: rows.length,
    hostsAnalyzed: new Set(rows.map(r => r.src)).size,
    uniqueHostsSeen: hosts.size,
    learningRecords: learning.length,
    evaluationRecords: evaluation.length,
    learningStart: new Date(start).toISOString(),
    evaluationStart: new Date(split).toISOString(),
    dataEnd: new Date(end).toISOString(),
    anomalies
  };
}

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", service: "NetWatch API", time: new Date().toISOString() });
});

app.post("/api/analyze", (req, res) => {
  try {
    const { records, config } = req.body || {};
    if (!Array.isArray(records)) return res.status(400).json({ error: "Body must contain a records array." });
    if (records.length > 200_000) return res.status(413).json({ error: "Maximum 200,000 records per request." });
    const result = analyzeRecords(records, config || {});
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message || "Analysis failed." });
  }
});

// Serve the existing NetWatch single-page frontend.
app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`NetWatch running at http://localhost:${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});
