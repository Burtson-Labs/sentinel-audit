/**
 * Where a response header is *actually* configured.
 *
 * A rule that asserts "this application ships no HSTS" after reading only nginx
 * configs and Dockerfiles is wrong for most of the deployments it will ever see.
 * The header is normally set at the edge — an ingress annotation, a Traefik
 * middleware, a CDN rule — and in a Kubernetes repository that edge lives in a
 * Helm chart, spelled in a vocabulary that does not contain the header's name:
 *
 *     nginx.ingress.kubernetes.io/hsts: "true"
 *     nginx.ingress.kubernetes.io/hsts-max-age: "31536000"
 *
 * Nothing in that block matches `/Strict-Transport-Security/`, so a name search
 * reports the header missing on a deployment that has it. This module exists so
 * an absence claim is made against every surface that could carry the header,
 * and so the claim is *downgraded* rather than asserted when a surface exists
 * that cannot be read statically.
 */

/** How a single security header can be expressed, across edge vocabularies. */
export interface HeaderSpec {
  name: string;
  why: string;
  /** Any match means the header is configured somewhere. */
  patterns: RegExp[];
}

export const SECURITY_HEADERS: HeaderSpec[] = [
  {
    name: 'Content-Security-Policy',
    why: 'decides whether an injected script can execute or exfiltrate',
    patterns: [
      /Content-Security-Policy/i,
      /contentSecurityPolicy/i, // helmet, and Traefik's Middleware headers block
    ],
  },
  {
    name: 'Strict-Transport-Security',
    why: 'prevents a downgrade to plaintext on the next visit',
    patterns: [
      /Strict-Transport-Security/i,
      // ingress-nginx annotation family: hsts, hsts-max-age,
      // hsts-include-subdomains, hsts-preload.
      /nginx\.ingress\.kubernetes\.io\/hsts/i,
      // Traefik Middleware headers block.
      /\bsts(?:Seconds|IncludeSubdomains|Preload)\s*:/i,
      /\bforceSTSHeader\s*:/i,
      // Caddy, and Helm values that name the feature rather than the header.
      /\b(?:enable|force)?hsts\s*:/i,
    ],
  },
  {
    name: 'X-Content-Type-Options',
    why: 'stops MIME sniffing turning an upload into script',
    patterns: [/X-Content-Type-Options/i, /\bcontentTypeNosniff\s*:/i],
  },
  {
    name: 'Referrer-Policy',
    why: 'keeps URLs (and ids in them) out of third-party logs',
    patterns: [/Referrer-Policy/i, /\breferrerPolicy\s*:/i],
  },
  {
    name: 'X-Frame-Options or frame-ancestors',
    why: 'prevents clickjacking of authenticated views',
    patterns: [/X-Frame-Options|frame-ancestors/i, /\b(?:frameDeny|customFrameOptionsValue)\s*:/i],
  },
];

export function headerSpec(name: string): HeaderSpec | undefined {
  return SECURITY_HEADERS.find((h) => h.name === name);
}

/** Is this header configured anywhere in `text`? */
export function declaresHeader(spec: HeaderSpec, text: string): boolean {
  return spec.patterns.some((re) => re.test(text));
}

/**
 * Paths that can carry response-header configuration.
 *
 * Deliberately generous. A file that turns out to say nothing costs one grep; a
 * surface that is never opened costs a false "the header is absent".
 */
export function isEdgeConfigPath(path: string): boolean {
  if (/node_modules\//.test(path)) return false;
  return (
    // Helm charts and raw manifests
    /(^|\/)charts?\//i.test(path) ||
    /(^|\/)(k8s|kubernetes|manifests|deploy|deployment|infra|infrastructure)\//i.test(path) ||
    /(^|\/)values[\w.-]*\.ya?ml$/i.test(path) ||
    /(^|\/)templates\/.*\.ya?ml$/i.test(path) ||
    /ingress[\w.-]*\.ya?ml$/i.test(path) ||
    // Reverse proxies and static hosts
    /nginx|\.conf$|Caddyfile|traefik|haproxy|httpd|apache/i.test(path) ||
    /(^|\/)_headers$/.test(path) ||
    /(vercel\.json|netlify\.toml|staticwebapp\.config\.json|firebase\.json|now\.json)$/i.test(path) ||
    // Node-side header middleware
    /(vite|next)\.config\.[cm]?[jt]s$/i.test(path) ||
    /(^|\/)server\.[cm]?[jt]s$/i.test(path) ||
    /\.html?$/i.test(path)
  );
}

/** Does this YAML actually describe an ingress/edge object? */
export function isKubernetesEdgeConfig(text: string): boolean {
  return (
    /kind:\s*Ingress\b/.test(text) ||
    /kind:\s*Middleware\b/.test(text) ||
    /kind:\s*HTTPRoute\b/.test(text) ||
    /networking\.k8s\.io/.test(text) ||
    /\bingress\s*:/.test(text) ||
    /nginx\.ingress\.kubernetes\.io\//.test(text) ||
    /traefik\.ingress\.kubernetes\.io\//.test(text)
  );
}

export interface EdgeSurvey {
  /** Edge-config files that were read. */
  surfaces: string[];
  /**
   * Edge configuration that exists but whose effect cannot be determined from
   * the repository alone. Non-empty means an absence claim must not be
   * `confirmed`, because the header may well be set in something we cannot see.
   */
  unresolved: string[];
}

/**
 * Which edge surfaces exist, and which of them we cannot follow to a conclusion.
 *
 * The second list is the important one. "I checked six files and found nothing"
 * is a finding; "I checked six files, and a seventh points at a Traefik
 * middleware that is not in this repository" is a question. Reporting the second
 * as the first is the specific failure this module was written after.
 */
export function surveyEdgeConfig(texts: Iterable<readonly [string, string]>): EdgeSurvey {
  // Two passes on purpose. Whether a chart template's annotations are resolvable
  // depends on whether that chart's values file is also in the tree, and a
  // single pass answers that question with however much of the tree it has
  // walked so far — which is a verdict that changes with directory ordering.
  const entries = Array.from(texts).filter(([path]) => isEdgeConfigPath(path));
  const surfaces = entries.map(([path]) => path);
  const unresolved: string[] = [];
  const middlewareRefs = new Map<string, string>(); // middleware name -> referencing path
  const definedMiddleware = new Set<string>();

  for (const [, text] of entries) {
    if (!/kind:\s*Middleware\b/.test(text)) continue;
    for (const m of text.matchAll(/^\s*name:\s*["']?([\w.-]+)/gm)) definedMiddleware.add(m[1]!);
  }

  for (const [path, text] of entries) {
    // A snippet whose body is a template expression cannot be evaluated here:
    // the header may well be in the rendered output.
    for (const m of text.matchAll(/(configuration-snippet|server-snippet|location-snippet)\s*:\s*\|?-?\s*([^\n]*)/g)) {
      const body = m[2] ?? '';
      if (/\{\{|\$\{/.test(body)) unresolved.push(`${path} — ${m[1]} is a template expression, rendered value not inspectable`);
    }

    // Annotations pulled wholesale from values. Resolvable only if this chart's
    // own values file is in the tree.
    if (/toYaml\s+\.Values\.[\w.]*[Aa]nnotations/.test(text) && !chartValuesPresent(path, surfaces)) {
      unresolved.push(`${path} — ingress annotations come from a values file that is not in this repository`);
    }

    // Header config sourced from a ConfigMap/Secret rather than declared inline.
    if (/kind:\s*Ingress\b/.test(text) && /configMapRef|configMapKeyRef|secretKeyRef/.test(text)) {
      unresolved.push(`${path} — edge configuration is sourced from a ConfigMap/Secret whose contents are not in this repository`);
    }

    for (const m of text.matchAll(/router\.middlewares\s*:\s*["']?([^"'\n]+)/g)) {
      for (const ref of (m[1] ?? '').split(',')) {
        const trimmed = ref.trim();
        if (trimmed === '') continue;
        // Traefik references are `<namespace>-<name>@kubernetescrd`.
        const withoutProvider = trimmed.split('@')[0]!;
        const parts = withoutProvider.split('-');
        middlewareRefs.set(parts.length > 1 ? parts.slice(1).join('-') : withoutProvider, path);
      }
    }
  }

  for (const [name, path] of middlewareRefs) {
    if (definedMiddleware.has(name)) continue;
    unresolved.push(`${path} — references Traefik middleware "${name}", which is not defined in this repository`);
  }

  return { surfaces, unresolved };
}

/** Does the chart that owns `templatePath` ship a values file we can read? */
function chartValuesPresent(templatePath: string, surfaces: string[]): boolean {
  const idx = templatePath.lastIndexOf('/templates/');
  const chartRoot = idx >= 0 ? templatePath.slice(0, idx + 1) : '';
  return surfaces.some((p) => p.startsWith(chartRoot) && /(^|\/)values[\w.-]*\.ya?ml$/i.test(p));
}
