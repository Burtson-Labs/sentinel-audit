import { ALL_RULES } from '../rules/index.js';
import { isConfirmed, isProofConfirmed, isPatternConfirmed } from '../schema.js';
import type { Finding, FindingStatus, ScanContext, Severity } from '../types.js';

/**
 * SARIF 2.1.0 output — the automation bridge.
 *
 * Two choices worth knowing about:
 *
 * 1. **Refuted and triaged-out findings are emitted with `suppressions`.**
 *    GitHub code scanning then shows them as closed/suppressed rather than
 *    hiding them. That preserves the audit trail: a later run that stops
 *    refuting a finding makes it reappear, which is the behaviour you want.
 *
 * 2. **The verification result travels in the message and in properties.**
 *    `properties.sentinel.status` / `.verification` let a consumer filter on
 *    "confirmed only", which is the whole point of the schema.
 */

const LEVEL: Record<Severity, 'error' | 'warning' | 'note' | 'none'> = {
  Blocker: 'error',
  High: 'error',
  Medium: 'warning',
  Low: 'note',
  Info: 'note',
};

const PRECISION: Record<FindingStatus, 'very-high' | 'high' | 'medium' | 'low'> = {
  'proof-confirmed': 'very-high',
  'pattern-confirmed': 'high',
  plausible: 'medium',
  refuted: 'low',
  'triaged-out': 'low',
};

const SECURITY_SEVERITY: Record<Severity, string> = {
  Blocker: '9.5',
  High: '7.5',
  Medium: '5.0',
  Low: '3.0',
  Info: '1.0',
};

export interface SarifOptions {
  toolVersion: string;
  informationUri?: string;
}

export function buildSarif(ctx: ScanContext, findings: Finding[], options: SarifOptions): string {
  const ruleIds = Array.from(new Set(findings.map((f) => f.ruleId ?? f.id)));
  const rules = ruleIds.map((id) => {
    const rule = ALL_RULES.find((r) => r.id === id);
    const sample = findings.find((f) => (f.ruleId ?? f.id) === id)!;
    return {
      id,
      name: toPascal(id),
      shortDescription: { text: rule?.title ?? sample.title },
      fullDescription: { text: rule?.why ?? sample.whyThisMatters },
      help: {
        text: rule?.recommendation ?? sample.recommendation,
        markdown: `**Recommendation**\n\n${rule?.recommendation ?? sample.recommendation}\n\n**Acceptance criteria**\n\n${(rule?.acceptance ?? sample.acceptanceCriteria).map((a) => `- ${a}`).join('\n')}`,
      },
      defaultConfiguration: { level: LEVEL[sample.severity] },
      properties: {
        tags: [
          ...new Set([
            ...(rule?.labels ?? sample.suggestedLabels),
            ...sample.standards.cwe,
            ...sample.standards.owasp.map((o) => o.replace(/\s+/g, '-')),
            `claim-type:${sample.verification.claimType}`,
          ]),
        ],
        'security-severity': SECURITY_SEVERITY[sample.severity],
        // `precision` is SARIF's vocabulary for the same distinction: a proof
        // that ran is very-high, a re-matched pattern is high (the construct is
        // real, the consequence unproven), a refutation is low.
        precision: PRECISION[sample.status],
      },
    };
  });

  const results = findings.flatMap((f) => {
    const locations = (f.locations.length > 0 ? f.locations : [{ file: 'package.json', startLine: 1 }]).slice(0, 10).map((loc) => ({
      physicalLocation: {
        artifactLocation: { uri: loc.file, uriBaseId: '%SRCROOT%' },
        region: {
          startLine: Math.max(1, loc.startLine),
          ...(loc.endLine && loc.endLine > loc.startLine ? { endLine: loc.endLine } : {}),
          ...(loc.excerpt ? { snippet: { text: loc.excerpt } } : {}),
        },
      },
    }));

    const suppressed = f.status === 'refuted' || f.status === 'triaged-out';
    return [
      {
        ruleId: f.ruleId ?? f.id,
        level: suppressed ? 'none' : LEVEL[f.severity],
        message: { text: sarifMessage(f) },
        locations,
        partialFingerprints: { sentinelFingerprint: f.fingerprint },
        ...(suppressed
          ? {
              suppressions: [
                {
                  kind: 'external' as const,
                  status: 'accepted' as const,
                  justification:
                    f.status === 'refuted'
                      ? `Refuted by Sentinel verification: ${f.verification.notes}`
                      : `Triaged out (${f.triage?.by ?? 'heuristic'}): ${f.triage?.reason ?? 'no reason recorded'} [${f.triage?.evidenceCited ?? ''}]`,
                },
              ],
            }
          : {}),
        properties: {
          sentinel: {
            findingId: f.id,
            status: f.status,
            /** The pre-0.2.0 coarse vocabulary, for consumers filtering on it. */
            statusClass: f.verification.class,
            severity: f.severity,
            confidence: f.confidence,
            claimType: f.verification.claimType,
            verificationMethod: f.verification.method,
            verificationResult: f.verification.result,
            proofCommand: f.verification.proof?.command,
            proofVerdict: f.verification.proof?.verdict,
            agentExecutable: f.fixPlan.agentExecutable,
            effort: f.effortEstimate,
            standards: [...f.standards.cwe, ...f.standards.owasp, ...f.standards.controls.map((c) => c.id)],
          },
        },
      },
    ];
  });

  const doc = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'sentinel-audit',
            version: options.toolVersion,
            semanticVersion: options.toolVersion,
            informationUri: options.informationUri ?? 'https://github.com/Burtson-Labs/sentinel-audit',
            rules,
          },
        },
        results,
        automationDetails: {
          id: `sentinel-audit/${ctx.profileId}/`,
          description: { text: `Sentinel audit with profile ${ctx.profileId}` },
        },
        versionControlProvenance:
          ctx.recon.commitSha && ctx.recon.commitSha !== 'unknown'
            ? [
                {
                  repositoryUri: ctx.recon.repoUrl,
                  revisionId: ctx.recon.commitSha,
                  branch: ctx.recon.branch,
                },
              ]
            : undefined,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: ctx.startedAt,
            endTimeUtc: ctx.finishedAt ?? new Date().toISOString(),
            toolExecutionNotifications: ctx.runs
              .filter((r) => !r.ok)
              .map((r) => ({ level: 'warning' as const, message: { text: `${r.name}: ${r.note}` } })),
          },
        ],
        properties: {
          sentinel: {
            profile: ctx.profileId,
            llmPass: ctx.llm.available ? 'ran' : 'not-run',
            counts: {
              proofConfirmed: findings.filter((f) => isProofConfirmed(f)).length,
              patternConfirmed: findings.filter((f) => isPatternConfirmed(f)).length,
              confirmed: findings.filter((f) => isConfirmed(f)).length,
              plausible: findings.filter((f) => f.status === 'plausible').length,
              refuted: findings.filter((f) => f.status === 'refuted').length,
              triagedOut: findings.filter((f) => f.status === 'triaged-out').length,
            },
          },
        },
      },
    ],
  };

  return `${JSON.stringify(doc, null, 2)}\n`;
}

const TAG: Record<FindingStatus, string> = {
  'proof-confirmed': 'PROOF-CONFIRMED',
  'pattern-confirmed': 'PATTERN-CONFIRMED',
  plausible: 'PLAUSIBLE',
  refuted: 'REFUTED',
  'triaged-out': 'TRIAGED OUT',
};

function sarifMessage(f: Finding): string {
  const proof = f.verification.proof ? ` Proof: ${f.verification.proof.command} → ${f.verification.proof.verdict}.` : '';
  const caveat = isPatternConfirmed(f)
    ? ' The pattern was re-matched on disk; exploitability is unproven.'
    : '';
  return `[${TAG[f.status]}] ${f.title}. ${f.evidence} — ${f.verification.notes}${caveat}${proof}`;
}

function toPascal(id: string): string {
  return id
    .split(/[-_]/)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase())
    .join('');
}
