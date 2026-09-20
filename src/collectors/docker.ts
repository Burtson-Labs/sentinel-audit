import { join } from 'node:path';
import { readTextSafe } from '../util/fsx.js';
import type { CollectorRun, DockerResult } from '../types.js';

/**
 * Dockerfile collector: base-image pinning, root user, secrets in build args,
 * healthcheck, and `ADD` of remote URLs.
 *
 * Multi-stage builds are handled: only the *final* stage decides whether the
 * runtime container runs as root, so a `USER node` in a builder stage does not
 * count. This is a common false positive in naive scanners.
 */

const SECRET_ARG = /(secret|token|password|passwd|api[_-]?key|apikey|private[_-]?key|credential|auth)/i;

export interface DockerOutput {
  docker: DockerResult;
  run: CollectorRun;
}

export function collectDocker(root: string, dockerfiles: string[]): DockerOutput {
  const started = Date.now();
  const files: DockerResult['files'] = [];
  for (const rel of dockerfiles) {
    const text = readTextSafe(join(root, rel));
    if (text === null) continue;
    files.push(analyseDockerfile(rel, text));
  }
  return {
    docker: { files },
    run: {
      name: 'docker',
      ok: true,
      durationMs: Date.now() - started,
      note: files.length === 0 ? 'no Dockerfiles found' : `${files.length} Dockerfile(s) analysed`,
      notExamined: [
        'built image contents (no image is built or pulled) — base-image CVEs need a container scanner such as trivy/grype',
        'docker-compose and Kubernetes manifests: securityContext is not evaluated',
      ],
    },
  };
}

export function analyseDockerfile(file: string, text: string): DockerResult['files'][number] {
  const lines = text.split('\n');
  const baseImages: Array<{ image: string; pinned: boolean; line: number }> = [];
  const secretsInArgs: Array<{ line: number; name: string }> = [];
  const addUsed: Array<{ line: number }> = [];
  let healthcheck = false;

  // Track stages so we can decide the FINAL stage's user.
  interface Stage { alias: string | null; userLine: number | null; user: string | null; startLine: number }
  const stages: Stage[] = [];
  const stageAliases = new Set<string>();

  for (const [i, raw] of lines.entries()) {
    const line = raw.trim();
    const lineNo = i + 1;
    if (line.length === 0 || line.startsWith('#')) continue;

    const from = /^FROM\s+(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (from?.[1]) {
      const image = from[1];
      const alias = from[2] ?? null;
      if (alias) stageAliases.add(alias.toLowerCase());
      // a FROM that references an earlier stage is not an external base image
      const referencesStage = stageAliases.has(image.toLowerCase()) && image !== from[1].toLowerCase() ? true : stageAliases.has(image.toLowerCase());
      if (!referencesStage) {
        baseImages.push({ image, pinned: image.includes('@sha256:'), line: lineNo });
      }
      stages.push({ alias, userLine: null, user: null, startLine: lineNo });
      continue;
    }

    const user = /^USER\s+(\S+)/i.exec(line);
    if (user?.[1]) {
      const current = stages[stages.length - 1];
      if (current) {
        current.user = user[1];
        current.userLine = lineNo;
      }
      continue;
    }

    const arg = /^(?:ARG|ENV)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=?/i.exec(line);
    // OAuth TOKEN_URL / AUTH_URL values are public endpoint locations, not
    // authenticators. Treating the noun without its qualifier made ordinary
    // OIDC configuration a High-severity secret finding.
    const publicEndpoint = arg?.[1] ? /(?:^|_)(?:URL|URI|ENDPOINT|HOST)$/i.test(arg[1]) : false;
    if (arg?.[1] && SECRET_ARG.test(arg[1]) && !publicEndpoint) {
      secretsInArgs.push({ line: lineNo, name: arg[1] });
    }

    if (/^HEALTHCHECK\b/i.test(line)) healthcheck = true;
    if (/^ADD\s+https?:\/\//i.test(line)) addUsed.push({ line: lineNo });
  }

  const finalStage = stages[stages.length - 1];
  const finalUser = finalStage?.user ?? null;
  const runsAsRoot = finalUser === null || finalUser === 'root' || finalUser === '0';

  return {
    file,
    baseImages,
    runsAsRoot,
    userLine: finalStage?.userLine ?? null,
    secretsInArgs,
    healthcheck,
    addUsed,
  };
}
