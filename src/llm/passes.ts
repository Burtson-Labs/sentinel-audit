import { join as joinPath } from 'node:path';
import { excerpt, writeFileEnsured } from '../util/fsx.js';
import { extractJson, type LlmProvider } from './client.js';
import type { Finding, ScanContext } from '../types.js';

/**
 * The three things a model is allowed to do in a Sentinel run.
 *
 * 1. **Triage** — dismiss a deterministic finding, but only by citing a
 *    file:line that proves the dismissal. A dismissal without a citation is
 *    rejected by the pass itself, and dismissed items stay in the report.
 * 2. **Review** — read the highest-signal files and propose findings the
 *    lexical rules cannot see (cross-module data flow, logic errors). Proposals
 *    are marked `source: 'llm'`, `method: 'code-read'`, and can therefore never
 *    be `confirmed`.
 * 3. **Fix-plan authoring** — turn a recommendation into an instruction an agent
 *    can execute.
 *
 * The model never decides a status, never sets a confidence number, and never
 * promotes its own findings. That is what keeps a bad model run from producing a
 * confident-looking bad report.
 */

export interface TriageDecision {
  id: string;
  verdict: 'keep' | 'dismiss' | 'downgrade';
  reason: string;
  evidence: string;
  severity?: Finding['severity'];
}

export interface LlmPassResult {
  triage: TriageDecision[];
  proposals: LlmProposal[];
  fixPlans: Array<{ id: string; agentPrompt: string; agentExecutable: boolean; rationale: string }>;
  calls: number;
  failures: number;
  notes: string[];
}

export interface LlmProposal {
  title: string;
  severity: Finding['severity'];
  type: Finding['type'];
  file: string;
  line: number;
  evidence: string;
  whyThisMatters: string;
  recommendation: string;
  confidenceSelfReported: string;
}

const EVIDENCE_CITATION = /[\w./-]+:\d+/;

/**
 * Optional prompt/response dump, enabled with SENTINEL_LLM_DEBUG=<dir>.
 *
 * A model pass that fails is almost always a prompt or a parsing problem, and
 * "returned no parseable JSON" is not enough to tell which. Writing the exact
 * exchange to disk turns a day of guessing into one `cat`.
 */
function dumpExchange(label: string, prompt: string, response: string): void {
  const dir = process.env.SENTINEL_LLM_DEBUG;
  if (!dir) return;
  try {
    const safe = label.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 80);
    writeFileEnsured(joinPath(dir, `${safe}.prompt.txt`), prompt);
    writeFileEnsured(joinPath(dir, `${safe}.response.txt`), response);
  } catch {
    // a debug dump that cannot be written must never break the scan
  }
}

export async function runLlmPasses(
  provider: LlmProvider,
  ctx: ScanContext,
  findings: Finding[],
  options: { maxReviewFiles?: number; texts: Map<string, string>; timeoutMs?: number },
): Promise<LlmPassResult> {
  const timeoutMs = options.timeoutMs ?? 300_000;
  const result: LlmPassResult = { triage: [], proposals: [], fixPlans: [], calls: 0, failures: 0, notes: [] };
  if (!provider.available) {
    result.notes.push(`model pass skipped: ${provider.note}`);
    return result;
  }

  // ---- pass 1: triage -----------------------------------------------------
  const triageable = findings
    .filter((f) => f.status !== 'refuted' && !f.triage?.suppressed)
    .slice(0, 40)
    .map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      status: f.status,
      evidence: excerpt(f.evidence, 400),
      locations: f.locations.slice(0, 3).map((l) => `${l.file}:${l.startLine}`),
    }));

  if (triageable.length > 0) {
    const prompt = buildTriagePrompt(ctx, triageable);
    const res = await provider.complete(prompt, { timeoutMs });
    result.calls += 1;
    dumpExchange('triage', prompt, res.text || (res.error ?? ''));
    if (!res.ok) {
      result.failures += 1;
      result.notes.push(`triage pass failed: ${res.error ?? 'no output'} — all deterministic findings were kept as-is`);
    } else {
      const parsed = extractJson<TriageDecision[]>(res.text);
      if (!Array.isArray(parsed)) {
        result.failures += 1;
        result.notes.push(
          `triage pass returned no parseable JSON — all deterministic findings were kept as-is. Response began: ${excerpt(res.text, 300)}`,
        );
      } else {
        for (const d of parsed) {
          if (!d || typeof d.id !== 'string') continue;
          if ((d.verdict === 'dismiss' || d.verdict === 'downgrade') && !EVIDENCE_CITATION.test(String(d.evidence ?? ''))) {
            result.notes.push(
              `rejected a ${d.verdict} decision for ${d.id}: no file:line citation was supplied, and an uncited dismissal is not accepted`,
            );
            continue;
          }
          result.triage.push({
            id: d.id,
            verdict: d.verdict === 'dismiss' || d.verdict === 'downgrade' ? d.verdict : 'keep',
            reason: String(d.reason ?? '').slice(0, 600),
            evidence: String(d.evidence ?? '').slice(0, 300),
            severity: d.severity,
          });
        }
      }
    }
  }

  // ---- pass 2: deep review of the highest-signal files --------------------
  const reviewFiles = pickReviewFiles(ctx, findings, options.maxReviewFiles ?? 4);
  for (const file of reviewFiles) {
    const text = options.texts.get(file);
    if (!text) continue;
    const prompt = buildReviewPrompt(ctx, file, text.slice(0, 24_000));
    const res = await provider.complete(prompt, { timeoutMs });
    result.calls += 1;
    dumpExchange(`review-${file}`, prompt, res.text || (res.error ?? ''));
    if (!res.ok) {
      result.failures += 1;
      result.notes.push(`deep review of ${file} failed: ${res.error ?? 'no output'}`);
      continue;
    }
    const parsed = extractJson<LlmProposal[]>(res.text);
    if (!Array.isArray(parsed)) {
      result.failures += 1;
      result.notes.push(`deep review of ${file} returned no parseable JSON. Response began: ${excerpt(res.text, 300)}`);
      continue;
    }
    for (const p of parsed) {
      if (!p || typeof p.title !== 'string' || !p.file) continue;
      if (!EVIDENCE_CITATION.test(String(p.evidence ?? '')) && typeof p.line !== 'number') {
        result.notes.push(`rejected a proposed finding from ${file} ("${excerpt(String(p.title), 80)}"): no concrete location was cited`);
        continue;
      }
      result.proposals.push({
        title: String(p.title).slice(0, 200),
        severity: normaliseSeverity(p.severity),
        type: normaliseType(p.type),
        file: String(p.file),
        line: Number(p.line) || 1,
        evidence: String(p.evidence ?? '').slice(0, 600),
        whyThisMatters: String(p.whyThisMatters ?? '').slice(0, 1200),
        recommendation: String(p.recommendation ?? '').slice(0, 1200),
        confidenceSelfReported: String(p.confidenceSelfReported ?? 'unstated').slice(0, 120),
      });
    }
  }

  // ---- pass 3: fix plans for agent-executable findings --------------------
  const needPlans = findings.filter((f) => f.fixPlan.agentExecutable && !f.fixPlan.agentPrompt).slice(0, 8);
  if (needPlans.length > 0) {
    const prompt = buildFixPlanPrompt(ctx, needPlans);
    const res = await provider.complete(prompt, { timeoutMs });
    result.calls += 1;
    dumpExchange('fix-plans', prompt, res.text || (res.error ?? ''));
    if (!res.ok) {
      result.failures += 1;
      result.notes.push(`fix-plan pass failed: ${res.error ?? 'no output'} — the rule-authored plans were used instead`);
    } else {
      const parsed = extractJson<Array<{ id: string; agentPrompt: string; agentExecutable: boolean; rationale: string }>>(res.text);
      if (Array.isArray(parsed)) {
        for (const p of parsed) {
          if (!p?.id || typeof p.agentPrompt !== 'string') continue;
          result.fixPlans.push({
            id: p.id,
            agentPrompt: p.agentPrompt.slice(0, 4000),
            agentExecutable: p.agentExecutable !== false,
            rationale: String(p.rationale ?? '').slice(0, 600),
          });
        }
      } else {
        result.failures += 1;
        result.notes.push('fix-plan pass returned no parseable JSON');
      }
    }
  }

  result.proposals = dedupeProposals(result.proposals);
  return result;
}

/**
 * Collapse proposals that describe the same defect at several lines.
 *
 * A model asked to review a file will often report one problem once per
 * occurrence. Three tickets for one fix is the same noise a scanner produces,
 * so proposals with the same title in the same file become one finding whose
 * evidence names every line.
 */
export function dedupeProposals(proposals: LlmProposal[]): LlmProposal[] {
  const byKey = new Map<string, LlmProposal & { lines: number[] }>();
  for (const p of proposals) {
    const key = `${p.file}|${p.title.toLowerCase().replace(/\s+/g, ' ').trim()}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...p, lines: [p.line] });
      continue;
    }
    if (!existing.lines.includes(p.line)) existing.lines.push(p.line);
  }
  return Array.from(byKey.values()).map((p) => {
    if (p.lines.length <= 1) {
      const { lines: _lines, ...rest } = p;
      return rest;
    }
    const sorted = [...p.lines].sort((a, b) => a - b);
    const { lines: _lines, ...rest } = p;
    return {
      ...rest,
      line: sorted[0]!,
      evidence: `${p.evidence} (also at ${sorted.slice(1).map((l) => `${p.file}:${l}`).join(', ')})`,
    };
  });
}

function pickReviewFiles(ctx: ScanContext, findings: Finding[], max: number): string[] {
  const score = new Map<string, number>();
  const bump = (file: string, n: number): void => {
    score.set(file, (score.get(file) ?? 0) + n);
  };
  const weight: Record<string, number> = { Blocker: 10, High: 6, Medium: 3, Low: 1, Info: 0 };
  for (const f of findings) {
    for (const loc of f.locations) bump(loc.file, weight[f.severity] ?? 1);
  }
  // security-sensitive paths are interesting even with no rule hits
  for (const file of ctx.recon.entrypoints) bump(file, 2);
  for (const [file] of score) {
    if (/auth|login|session|token|secret|crypt|permission|admin|upload|download|proxy|exec/i.test(file)) bump(file, 5);
  }
  return Array.from(score.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([f]) => f)
    .filter((f) => /\.(ts|tsx|js|jsx|mts|cts)$/.test(f))
    .slice(0, max);
}

function normaliseSeverity(s: unknown): Finding['severity'] {
  const v = String(s);
  return v === 'Blocker' || v === 'High' || v === 'Medium' || v === 'Low' || v === 'Info' ? v : 'Medium';
}

function normaliseType(t: unknown): Finding['type'] {
  const v = String(t);
  const allowed: Finding['type'][] = ['Security', 'Supply Chain', 'Secret', 'Tech Debt', 'Quality', 'CI-CD', 'Compliance', 'Architecture', 'Testing'];
  return (allowed as string[]).includes(v) ? (v as Finding['type']) : 'Security';
}

// ---------------------------------------------------------------------------
// prompts
// ---------------------------------------------------------------------------

/**
 * Every analysis prompt opens with this.
 *
 * The provider may be a *coding agent*, not a completion endpoint — give it a
 * question and it will start listing files and reading source to answer it
 * properly. That is the right instinct for a coding task and exactly wrong
 * here: the prompt already carries everything needed, the exploration burns the
 * per-call budget, and the call gets killed mid-loop before the answer is
 * emitted. The symptom is "returned no parseable JSON" on every pass, which
 * looks like a parsing bug and is not one.
 */
const NO_TOOLS_PREAMBLE = [
  'Answer using only the information in this message.',
  'Do not read files, do not list directories, do not run commands, do not use any tool.',
  'Do not ask questions. Produce the requested output directly as your first and only action.',
].join(' ');

function repoSummary(ctx: ScanContext): string {
  return [
    `Repository: ${ctx.recon.repoUrl} @ ${ctx.recon.commitSha.slice(0, 12)} (${ctx.recon.branch})`,
    `Stack: ${ctx.recon.frameworks.join(', ') || 'unknown'}; package manager ${ctx.recon.packageManager}`,
    `Size: ${ctx.recon.totalFiles} files, ${ctx.recon.totalLoc} LOC, ${ctx.recon.testFileCount} test modules / ${ctx.recon.sourceFileCount} source modules`,
  ].join('\n');
}

function buildTriagePrompt(ctx: ScanContext, items: Array<{ id: string; title: string; severity: string; status: string; evidence: string; locations: string[] }>): string {
  return `${NO_TOOLS_PREAMBLE}

You are triaging the output of a static security scanner. Your job is to remove noise, not to be agreeable.

${repoSummary(ctx)}

Rules you must follow:
- You may answer "dismiss" or "downgrade" ONLY if you can cite a concrete file:line that proves the finding does not apply. An uncited dismissal will be discarded and the finding kept.
- A finding that is real but low-impact is "downgrade", not "dismiss".
- A finding you are unsure about is "keep". Uncertainty is not a reason to dismiss.
- Do not dismiss something merely because it is common practice, or because fixing it is inconvenient.

Findings:
${items.map((i) => `- ${i.id} [${i.severity}/${i.status}] ${i.title}\n  evidence: ${i.evidence}\n  locations: ${i.locations.join(', ')}`).join('\n')}

Reply with ONLY a JSON array, no prose:
[{"id":"SEC-001","verdict":"keep|dismiss|downgrade","reason":"one or two sentences","evidence":"path/to/file.ts:123 — what is there that justifies this","severity":"High"}]`;
}

function buildReviewPrompt(ctx: ScanContext, file: string, content: string): string {
  return `${NO_TOOLS_PREAMBLE} The complete file contents are included below — there is nothing to look up.

You are reviewing one file from a repository for security and correctness defects that a regex-based scanner cannot see: cross-module data flow, logic errors, missing authorisation, unsafe defaults, race conditions, and error handling that fails open.

${repoSummary(ctx)}

File: ${file}

\`\`\`
${content}
\`\`\`

Rules:
- Report only defects you can point at a specific line for. No generic advice.
- Do not report style, formatting, naming, or "consider adding tests".
- Do not report something as a vulnerability if the code already handles it — say so by simply not reporting it.
- If the file has no real defects, reply with an empty array. That is a valid and useful answer.
- State your own confidence honestly in confidenceSelfReported (e.g. "high — the sink is reached with no escaping", "low — depends on a caller I cannot see").

Reply with ONLY a JSON array, no prose:
[{"title":"short imperative title","severity":"Blocker|High|Medium|Low|Info","type":"Security|Quality|Tech Debt|Architecture|Testing","file":"${file}","line":123,"evidence":"${file}:123 — what the code does","whyThisMatters":"the consequence, concretely","recommendation":"the specific change","confidenceSelfReported":"high|medium|low — why"}]`;
}

function buildFixPlanPrompt(ctx: ScanContext, findings: Finding[]): string {
  return `${NO_TOOLS_PREAMBLE}

You are writing instructions for a coding agent that will implement each fix on its own branch, run the repository's test suite, and open a pull request for a human to review.

${repoSummary(ctx)}
Test command: ${ctx.recon.scripts.test ? `\`${ctx.recon.scripts.test}\`` : 'none detected'}

For each finding, write an instruction that is specific enough to execute without further questions and conservative enough that a wrong interpretation fails the tests rather than shipping silently.

Rules:
- Name exact files and the shape of the change.
- Include the test to add and what it must assert.
- Forbid scope creep: the agent must not reformat, rename, or "improve" anything else.
- If the fix genuinely needs a human decision (a policy value, an allowlist, a credential), set agentExecutable to false and say what decision is missing.

Findings:
${findings.map((f) => `- ${f.id} [${f.severity}] ${f.title}\n  evidence: ${excerpt(f.evidence, 300)}\n  recommendation: ${excerpt(f.recommendation, 300)}\n  files: ${f.fixPlan.files.map((x) => x.path).join(', ')}`).join('\n')}

Reply with ONLY a JSON array, no prose:
[{"id":"SEC-001","agentExecutable":true,"agentPrompt":"step by step instruction","rationale":"why this is safe to automate, or what decision is missing"}]`;
}

/** Merge model output into the deterministic findings, with provenance intact. */
export function applyLlmResults(findings: Finding[], pass: LlmPassResult): { applied: number; rejected: number } {
  let applied = 0;
  let rejected = 0;
  const byId = new Map(findings.map((f) => [f.id, f]));

  for (const d of pass.triage) {
    const f = byId.get(d.id);
    if (!f) continue;
    if (d.verdict === 'keep') continue;
    // A model may not overturn an executed proof. This is the guard that stops a
    // confident model from talking a verified finding out of the report.
    if (f.verification.method === 'proof-executed' && f.verification.proof?.verdict === 'vulnerable') {
      f.notes = [...(f.notes ?? []), `the model pass suggested "${d.verdict}" for this finding, which was rejected: an executed proof demonstrated the behaviour, and a model opinion does not overturn a proof. Model reason: ${d.reason}`];
      rejected += 1;
      continue;
    }
    if (d.verdict === 'dismiss') {
      f.status = 'triaged-out';
      f.triage = { suppressed: true, reason: d.reason, evidenceCited: d.evidence, by: 'llm' };
      applied += 1;
    } else if (d.verdict === 'downgrade') {
      const order: Finding['severity'][] = ['Info', 'Low', 'Medium', 'High', 'Blocker'];
      const target = d.severity && order.includes(d.severity) ? d.severity : order[Math.max(0, order.indexOf(f.severity) - 1)]!;
      f.notes = [...(f.notes ?? []), `severity lowered from ${f.severity} to ${target} by the model triage pass: ${d.reason} (${d.evidence})`];
      f.severity = target;
      applied += 1;
    }
  }

  for (const p of pass.fixPlans) {
    const f = byId.get(p.id);
    if (!f) continue;
    f.fixPlan.agentPrompt = p.agentPrompt;
    f.fixPlan.agentExecutable = f.fixPlan.agentExecutable && p.agentExecutable;
    if (!p.agentExecutable) f.fixPlan.notAgentExecutableReason = p.rationale;
    applied += 1;
  }

  return { applied, rejected };
}
