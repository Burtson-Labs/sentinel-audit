import type { ConfidenceAssessment, Finding, ScanContext, Severity } from '../types.js';
import type { Profile } from '../profile.js';
import { band } from './confidence.js';
import { isPatternConfirmed, isProofConfirmed } from '../schema.js';

/**
 * Self-contained HTML report. No network requests of any kind: no CDN script,
 * no web font, no remote image. An audit artefact that phones home is not an
 * audit artefact.
 */

const SEVERITY_ORDER: Severity[] = ['Blocker', 'High', 'Medium', 'Low', 'Info'];

export function renderHtml(ctx: ScanContext, findings: Finding[], profile: Profile, c: ConfidenceAssessment): string {
  const live = findings.filter((f) => f.status !== 'refuted' && f.status !== 'triaged-out');
  const proofConfirmed = findings.filter((f) => isProofConfirmed(f));
  const patternConfirmed = findings.filter((f) => isPatternConfirmed(f));
  const plausible = findings.filter((f) => f.status === 'plausible');
  const refuted = findings.filter((f) => f.status === 'refuted');
  const triaged = findings.filter((f) => f.status === 'triaged-out');
  const name = repoName(ctx);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel audit — ${esc(name)}</title>
<style>${CSS}</style>
</head>
<body>
<header class="top">
  <div class="wrap">
    <p class="eyebrow">${lucideIcon('shield-check')} sentinel-audit · ${esc(profile.title)}</p>
    <h1>${esc(name)}</h1>
    <p class="meta"><code>${esc(ctx.recon.commitSha.slice(0, 12))}</code> on <code>${esc(ctx.recon.branch)}</code> · ${new Date().toISOString().slice(0, 10)} · ${esc(ctx.recon.repoUrl)}</p>
    <div class="scorecards">
      ${card('Overall', `${c.overallScore}/10`, band(c.overallScore), scoreTone(c.overallScore))}
      ${card('Security posture', `${c.securityPostureScore}/10`, band(c.securityPostureScore), scoreTone(c.securityPostureScore))}
      ${card('Gate', c.gateDecision.replace('-', ' '), profile.gate.blockOn.join('/') + ' block', c.gateDecision === 'block' ? 'bad' : c.gateDecision === 'pass' ? 'good' : 'warn')}
      ${card('Confirmed share', `${Math.round(c.evidenceQuality.verifiedShare * 100)}%`, `of live findings confirmed by a check · ${Math.round(c.evidenceQuality.provenShare * 100)}% by an executed proof`, c.evidenceQuality.verifiedShare >= 0.5 ? 'good' : 'warn')}
    </div>
  </div>
</header>

<main class="wrap">
  <section class="panel">
    <h2>Verification summary</h2>
    <p>The two ways a check can agree are kept apart. <strong>Proof-confirmed</strong>: a generated script ran against the real code and demonstrated the behaviour. <strong>Pattern-confirmed</strong>: the construct was re-read from disk and re-matched — the pattern is genuinely there, but nothing showed it being exploited. Findings that did not survive checking stay in the report as <strong>refuted</strong>.</p>
    <div class="statrow">
      ${stat('Proof-confirmed', proofConfirmed.length, 'proof-confirmed')}
      ${stat('Pattern-confirmed', patternConfirmed.length, 'pattern-confirmed')}
      ${stat('Plausible', plausible.length, 'plausible')}
      ${stat('Refuted', refuted.length, 'refuted')}
      ${stat('Triaged out', triaged.length, 'triaged')}
    </div>
    <div class="sevbar">
      ${SEVERITY_ORDER.map((s) => {
        const n = live.filter((f) => f.severity === s).length;
        return n > 0 ? `<span class="sev sev-${s.toLowerCase()}">${s}: ${n}</span>` : '';
      }).join('')}
    </div>
  </section>

  <section class="panel">
    <h2>Reconnaissance</h2>
    <dl class="kv">
      <dt>Languages</dt><dd>${esc(ctx.recon.languages.slice(0, 5).map((l) => `${l.language} ${l.loc.toLocaleString()} LOC`).join(' · ') || 'none detected')}</dd>
      <dt>Frameworks</dt><dd>${esc(ctx.recon.frameworks.join(' · ') || 'none detected')}</dd>
      <dt>Size</dt><dd>${ctx.recon.totalFiles.toLocaleString()} files · ${ctx.recon.totalLoc.toLocaleString()} LOC</dd>
      <dt>Tests</dt><dd>${ctx.recon.testFileCount} test / ${ctx.recon.sourceFileCount} source modules (ratio ${ctx.recon.testToSourceRatio})</dd>
      <dt>Dependencies</dt><dd>${ctx.deps.total} installed · ${ctx.deps.advisories.length} advisory record(s) · ${esc(ctx.deps.auditCommand ?? 'audit unavailable')}</dd>
      <dt>CI</dt><dd>${ctx.ci.workflows.length} workflow(s) · gates: ${esc(gateList(ctx))}</dd>
      <dt>Analysis depth</dt><dd>${ctx.llm.available ? `collectors + lexical rules + model review (${ctx.llm.calls} call(s))` : 'collectors + lexical rules only — model pass did not run'}</dd>
    </dl>
  </section>

  <nav class="filters" aria-label="Filter findings">
    <button class="chip active" data-filter="all">All ${findings.length}</button>
    <button class="chip" data-filter="proof-confirmed">Proof-confirmed ${proofConfirmed.length}</button>
    <button class="chip" data-filter="pattern-confirmed">Pattern-confirmed ${patternConfirmed.length}</button>
    <button class="chip" data-filter="plausible">Plausible ${plausible.length}</button>
    <button class="chip" data-filter="refuted">Refuted ${refuted.length}</button>
    <button class="chip" data-filter="triaged-out">Triaged out ${triaged.length}</button>
    <button class="chip" data-filter="agent">Agent-fixable ${findings.filter((f) => f.fixPlan.agentExecutable).length}</button>
  </nav>

  <section id="findings">
    ${[...proofConfirmed.sort(bySeverity), ...patternConfirmed.sort(bySeverity), ...plausible.sort(bySeverity), ...refuted, ...triaged].map(findingCard).join('\n')}
  </section>

  <section class="panel">
    <h2>Why this score</h2>
    <h3>Why not lower</h3>
    <ul>${c.whyNotLower.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
    <h3>Why not higher</h3>
    <ul>${c.whyNotHigher.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
  </section>

  ${c.riskMatrix.length > 0
    ? `<section class="panel">
    <h2>Risk matrix</h2>
    <div class="tablescroll"><table>
      <thead><tr><th>ID</th><th>Risk</th><th>Likelihood</th><th>Impact</th><th>Level</th></tr></thead>
      <tbody>${c.riskMatrix.map((r) => `<tr><td><code>${esc(r.id)}</code></td><td>${esc(r.risk)}</td><td>${r.likelihood}</td><td>${r.impact}</td><td><span class="level level-${r.level.toLowerCase()}">${r.level}</span></td></tr>`).join('')}</tbody>
    </table></div>
    <p class="small">Likelihood comes from verification strength: an executed proof is High, a confirmed factual claim Medium, an unproven claim Low.</p>
  </section>`
    : ''}

  ${c.signals.length > 0
    ? `<section class="panel">
    <h2>Signals</h2>
    ${c.signals.map((s) => `<div class="signal"><p class="sig">${esc(s.signal)}</p><p class="interp">${esc(s.interpretation)}</p></div>`).join('')}
  </section>`
    : ''}

  <section class="panel">
    <h2>Remediation plan</h2>
    ${c.remediationPhases.map((p) => `<h3>${esc(p.phase)} <span class="small">${esc(p.estimate)}</span></h3><ul>${p.items.slice(0, 12).map((i) => `<li>${esc(i)}</li>`).join('')}${p.items.length > 12 ? `<li class="small">+${p.items.length - 12} more</li>` : ''}</ul>`).join('')}
  </section>

  <section class="panel">
    <h2>Bottom line</h2>
    <ul>${c.bottomLine.map((b) => `<li>${mdLite(b)}</li>`).join('')}</ul>
  </section>

  <footer>
    <p class="small">Generated by sentinel-audit · profile <code>${esc(profile.id)}</code> · commit <code>${esc(ctx.recon.commitSha)}</code> · scan ${esc(ctx.startedAt)} → ${esc(ctx.finishedAt ?? 'n/a')}</p>
    <p class="small">This page makes no network requests. Companion documents: REPORT.md, CONFIDENCE.md, COVERAGE.md, report.sarif, findings/*.json.</p>
  </footer>
</main>

<script>${JS}</script>
</body>
</html>
`;
}

function findingCard(f: Finding): string {
  const proof = f.verification.proof;
  return `<article class="finding" data-status="${f.status}" data-agent="${f.fixPlan.agentExecutable ? 'yes' : 'no'}">
  <header>
    <span class="badge badge-${f.status}">${lucideIcon(statusIcon(f.status))}${f.status.replace('-', ' ')}</span>
    <span class="sev sev-${f.severity.toLowerCase()}">${f.severity}</span>
    <h3><code>${esc(f.id)}</code> ${esc(f.title)}</h3>
    <p class="tags">${f.type} · confidence ${f.confidence.toFixed(2)} · effort ${f.effortEstimate} · ${esc(f.affectedArea)}${f.fixPlan.agentExecutable ? ' · <span class="agentable">agent-fixable</span>' : ''}</p>
  </header>
  <div class="body">
    <h4>Evidence</h4>
    <p class="mono">${esc(f.evidence)}</p>

    <h4>Verification <span class="small">(${esc(f.verification.state)} · ${esc(f.verification.method)} · ${esc(f.verification.claimType)} claim · ${esc(f.verification.result)})</span></h4>
    ${isPatternConfirmed(f) ? '<p class="small">Pattern-confirmed: the construct below was re-read from disk and re-matched. That establishes the pattern, not its exploitability.</p>' : ''}
    <ul class="checks">
      ${f.verification.checks.slice(0, 8).map((chk) => `<li class="chk chk-${chk.outcome}"><strong>${esc(chk.description)}</strong><br><span class="mono small">${esc(chk.detail)}</span></li>`).join('')}
    </ul>
    ${proof
      ? `<div class="proof">
      <p><strong>Proof executed:</strong> <code>${esc(proof.command)}</code> → <span class="verdict verdict-${proof.verdict}">${proof.verdict}</span> in ${proof.durationMs}ms (exit ${proof.exitCode})</p>
      <p class="small"><strong>Predicted:</strong> ${esc(proof.predicted)}</p>
      <p class="small"><strong>Observed:</strong> ${esc(proof.observed)}</p>
      ${proof.stdoutExcerpt ? `<pre class="small">${esc(proof.stdoutExcerpt)}</pre>` : ''}
    </div>`
      : ''}
    <p class="note">${esc(f.verification.notes)}</p>

    <h4>Why this matters</h4>
    <p>${esc(f.whyThisMatters)}</p>

    <h4>Standards</h4>
    <p class="small">${esc(f.standardMapping)}</p>

    <h4>Recommendation</h4>
    <p>${esc(f.recommendation)}</p>
    <ul>${f.acceptanceCriteria.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>

    <h4>Fix plan <span class="small">(${f.fixPlan.agentExecutable ? 'agent-executable' : 'needs a human decision'} · risk ${f.fixPlan.risk})</span></h4>
    <p>${esc(f.fixPlan.strategy)}</p>
    ${f.fixPlan.agentExecutable ? '' : `<p class="small">Not automated: ${esc(f.fixPlan.notAgentExecutableReason ?? 'no reason recorded')}</p>`}
    <ul class="small">${f.fixPlan.files.slice(0, 8).map((x) => `<li><code>${esc(x.path)}</code> — ${esc(x.change)}</li>`).join('')}</ul>
    ${f.triage ? `<h4>Triage</h4><p class="small">Suppressed by ${esc(f.triage.by)}: ${esc(f.triage.reason)} <code>${esc(f.triage.evidenceCited)}</code></p>` : ''}
    ${f.notes && f.notes.length > 0 ? `<h4>Notes</h4><ul class="small">${f.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}
  </div>
</article>`;
}

function card(label: string, value: string, sub: string, tone: string): string {
  return `<div class="scorecard tone-${tone}"><p class="label">${esc(label)}</p><p class="value">${esc(value)}</p><p class="sub">${esc(sub)}</p></div>`;
}

function stat(label: string, n: number, cls: string): string {
  return `<div class="statbox stat-${cls}"><span class="n">${n}</span><span class="l">${esc(label)}</span></div>`;
}

function scoreTone(n: number): string {
  if (n <= 3) return 'bad';
  if (n <= 5) return 'warn';
  if (n <= 7) return 'mid';
  return 'good';
}

function gateList(ctx: ScanContext): string {
  const gates = ['test', 'lint', 'typecheck', 'audit', 'sast', 'secrets'] as const;
  const on = gates.filter((g) => ctx.ci.workflows.some((w) => w.gates[g]));
  return on.length > 0 ? on.join(', ') : 'none';
}

function bySeverity(a: Finding, b: Finding): number {
  return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.confidence - a.confidence;
}

function repoName(ctx: ScanContext): string {
  const fromUrl = /([^/]+?)(?:\.git)?$/.exec(ctx.recon.repoUrl)?.[1];
  return fromUrl && fromUrl !== 'unknown' ? fromUrl : (ctx.root.split('/').pop() ?? 'repository');
}

function esc(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

type IconName = 'shield-check' | 'scan-eye' | 'triangle-alert' | 'circle-x';

function statusIcon(status: Finding['status']): IconName {
  if (status === 'proof-confirmed') return 'shield-check';
  if (status === 'pattern-confirmed') return 'scan-eye';
  if (status === 'refuted' || status === 'triaged-out') return 'circle-x';
  return 'triangle-alert';
}

/** Lucide-compatible inline paths keep the report readable and offline. */
function lucideIcon(name: IconName): string {
  const paths: Record<IconName, string> = {
    'shield-check': '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3z"/><path d="m9 12 2 2 4-4"/>',
    'scan-eye': '<path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="3"/>',
    'triangle-alert': '<path d="m21.7 18-8-14a2 2 0 0 0-3.4 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3"/><path d="M12 9v4M12 17h.01"/>',
    'circle-x': '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/>',
  };
  return `<svg class="icon" aria-hidden="true" viewBox="0 0 24 24">${paths[name]}</svg>`;
}

/** Bold-only markdown, for the bottom-line bullets. */
function mdLite(s: string): string {
  return esc(s).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
}

const CSS = `
:root {
  color-scheme: light dark;
  --bg: #fbfbfc; --panel: #ffffff; --ink: #16181d; --muted: #5d6370; --line: #e2e5ea;
  --accent: #2f5fd8; --good: #1f7a4d; --warn: #9a6508; --bad: #b3261e; --mid: #5a6b12;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #0f1115; --panel: #161a20; --ink: #e7e9ee; --muted: #9aa1ae; --line: #262c35;
    --accent: #7aa2ff; --good: #56c98a; --warn: #e0b050; --bad: #ff7b72; --mid: #b7d14a; }
}
:root[data-theme="dark"] { --bg: #0f1115; --panel: #161a20; --ink: #e7e9ee; --muted: #9aa1ae; --line: #262c35;
  --accent: #7aa2ff; --good: #56c98a; --warn: #e0b050; --bad: #ff7b72; --mid: #b7d14a; }
:root[data-theme="light"] { --bg: #fbfbfc; --panel: #ffffff; --ink: #16181d; --muted: #5d6370; --line: #e2e5ea;
  --accent: #2f5fd8; --good: #1f7a4d; --warn: #9a6508; --bad: #b3261e; --mid: #5a6b12; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.6 var(--sans); overflow-x: hidden; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 20px; }
.top { border-bottom: 1px solid var(--line); padding: 32px 0 24px; background: var(--panel); }
.eyebrow { margin: 0 0 6px; font: 600 11px/1 var(--mono); letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
.icon { width: 14px; height: 14px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; vertical-align: -3px; margin-right: 5px; }
h1 { margin: 0 0 6px; font-size: clamp(24px, 4vw, 34px); letter-spacing: -.02em; }
.meta { margin: 0; color: var(--muted); font-size: 13px; }
.scorecards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 22px; }
.scorecard { border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; background: var(--bg); }
.scorecard .label { margin: 0; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.scorecard .value { margin: 4px 0 2px; font: 700 26px/1 var(--sans); letter-spacing: -.02em; }
.scorecard .sub { margin: 0; font-size: 12px; color: var(--muted); }
.tone-good .value { color: var(--good); } .tone-mid .value { color: var(--mid); }
.tone-warn .value { color: var(--warn); } .tone-bad .value { color: var(--bad); }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 20px 22px; margin: 20px 0; }
.panel h2 { margin: 0 0 10px; font-size: 19px; letter-spacing: -.01em; }
.panel h3 { margin: 18px 0 6px; font-size: 15px; }
.statrow { display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0 10px; }
.statbox { border: 1px solid var(--line); border-radius: 10px; padding: 10px 14px; min-width: 110px; background: var(--bg); }
.statbox .n { display: block; font: 700 22px/1.1 var(--sans); }
.statbox .l { font-size: 12px; color: var(--muted); }
.stat-proof-confirmed .n { color: var(--bad); } .stat-pattern-confirmed .n { color: var(--mid); }
.stat-plausible .n { color: var(--warn); }
.stat-refuted .n { color: var(--good); } .stat-triaged .n { color: var(--muted); }
.sevbar { display: flex; flex-wrap: wrap; gap: 8px; }
.sev { font: 600 11px/1 var(--mono); padding: 5px 8px; border-radius: 999px; border: 1px solid var(--line); white-space: nowrap; }
.sev-blocker { color: var(--bad); border-color: var(--bad); }
.sev-high { color: var(--bad); } .sev-medium { color: var(--warn); }
.sev-low { color: var(--muted); } .sev-info { color: var(--muted); }
.kv { display: grid; grid-template-columns: minmax(120px, 180px) 1fr; gap: 6px 16px; margin: 0; }
.kv dt { color: var(--muted); font-size: 13px; }
.kv dd { margin: 0; font-size: 14px; overflow-wrap: anywhere; }
.filters { display: flex; flex-wrap: wrap; gap: 8px; margin: 22px 0 8px; }
.chip { font: 600 12px/1 var(--sans); padding: 8px 12px; border-radius: 999px; border: 1px solid var(--line);
  background: var(--panel); color: var(--ink); cursor: pointer; }
.chip.active { border-color: var(--accent); color: var(--accent); }
.finding { background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--line); border-radius: 12px; padding: 18px 20px; margin: 12px 0; }
.finding[data-status="proof-confirmed"] { border-left-color: var(--bad); }
.finding[data-status="pattern-confirmed"] { border-left-color: var(--mid); }
.finding[data-status="plausible"] { border-left-color: var(--warn); }
.finding[data-status="refuted"] { border-left-color: var(--good); }
.finding[data-status="triaged-out"] { border-left-color: var(--muted); opacity: .82; }
.finding header { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.finding h3 { margin: 0; font-size: 16px; flex: 1 1 100%; letter-spacing: -.01em; }
.badge { font: 700 10px/1 var(--mono); letter-spacing: .08em; text-transform: uppercase; padding: 5px 8px; border-radius: 5px; }
.badge-proof-confirmed { background: var(--bad); color: #fff; }
.badge-pattern-confirmed { background: var(--mid); color: #fff; }
.badge-plausible { background: var(--warn); color: #fff; }
.badge-refuted { background: var(--good); color: #fff; }
.badge-triaged-out { background: var(--muted); color: #fff; }
.tags { flex: 1 1 100%; margin: 2px 0 0; font-size: 12px; color: var(--muted); }
.agentable { color: var(--accent); font-weight: 600; }
.finding h4 { margin: 16px 0 4px; font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.finding p { margin: 0 0 8px; }
.mono { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }
.small { font-size: 12px; color: var(--muted); }
.checks { list-style: none; padding: 0; margin: 0 0 8px; }
.chk { border-left: 2px solid var(--line); padding: 4px 0 4px 10px; margin: 0 0 6px; font-size: 13px; }
.chk-pass { border-left-color: var(--bad); } .chk-fail { border-left-color: var(--good); } .chk-skip { border-left-color: var(--muted); }
.proof { border: 1px dashed var(--line); border-radius: 8px; padding: 10px 12px; margin: 8px 0; background: var(--bg); }
.verdict { font: 700 11px/1 var(--mono); text-transform: uppercase; padding: 3px 6px; border-radius: 4px; }
.verdict-vulnerable { background: var(--bad); color: #fff; }
.verdict-safe { background: var(--good); color: #fff; }
.verdict-inconclusive, .verdict-error { background: var(--muted); color: #fff; }
.note { font-size: 13px; color: var(--muted); border-left: 2px solid var(--accent); padding-left: 10px; }
pre { overflow-x: auto; background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; font-family: var(--mono); }
code { font-family: var(--mono); font-size: .92em; }
.tablescroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.level { font: 600 11px/1 var(--mono); padding: 3px 6px; border-radius: 4px; }
.level-critical, .level-high { color: var(--bad); } .level-medium { color: var(--warn); } .level-low { color: var(--muted); }
.signal { border-left: 2px solid var(--accent); padding-left: 12px; margin: 0 0 14px; }
.signal .sig { font-weight: 600; margin: 0 0 4px; }
.signal .interp { margin: 0; color: var(--muted); }
ul { margin: 0 0 8px; padding-left: 20px; }
li { margin: 0 0 4px; }
footer { padding: 20px 0 40px; border-top: 1px solid var(--line); margin-top: 24px; }
img { max-width: 100%; }
`;

const JS = `
(function () {
  var chips = document.querySelectorAll('.chip');
  var cards = document.querySelectorAll('.finding');
  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chips.forEach(function (c) { c.classList.remove('active'); });
      chip.classList.add('active');
      var f = chip.getAttribute('data-filter');
      cards.forEach(function (card) {
        var show = f === 'all'
          || (f === 'agent' ? card.getAttribute('data-agent') === 'yes' : card.getAttribute('data-status') === f);
        card.style.display = show ? '' : 'none';
      });
    });
  });
})();
`;
