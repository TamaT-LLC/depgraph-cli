import path from "node:path";
import { readUtf8, normalizeRelative } from "./fs";
import { stableId } from "./ids";
import { compareUtf8, type GraphNode, type JsonValue } from "./types";

export interface PackageRecord {
  absolutePath: string;
  relativePath: string;
  manifestPath: string;
  manifest: Record<string, unknown>;
  name: string;
  version: string;
  locator: string;
  id: string;
  dependencies: Map<string, { range: string; section: DependencySection }>;
}

export interface LockInstance {
  version: string;
  /** A manager-native, repository-relative identity for this exact install instance. */
  locator: string;
}

export type DependencySection = "dependencies" | "devDependencies" | "peerDependencies" | "optionalDependencies";

export interface WorkspaceIssue {
  code:
    | "web.package_manifest_read_failed"
    | "web.package_manifest_invalid"
    | "web.lockfile_unsupported"
    | "web.lockfile_invalid"
    | "web.package_manager_ambiguous";
  path: string;
  reason: string;
}

export interface Workspace {
  root: string;
  repositoryIdentity: string;
  rootManifest: Record<string, unknown> | null;
  packages: PackageRecord[];
  packageByName: Map<string, PackageRecord[]>;
  manager: string;
  lockfile: string | null;
  lockInstances: Map<string, LockInstance[]>;
  workspaceNode: GraphNode;
  issues: WorkspaceIssue[];
  ignoredManifestPaths: string[];
}

export interface PackageInstallSelection {
  workspacePackages: PackageRecord[];
  externalInstances: LockInstance[];
  precision: "exact" | "overapprox" | "heuristic";
  reason: string | null;
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function dependenciesOf(manifest: Record<string, unknown>): PackageRecord["dependencies"] {
  const dependencies: PackageRecord["dependencies"] = new Map();
  // Later production sections override weaker declarations. In particular,
  // npm treats optionalDependencies as overriding the same dependency entry.
  for (const section of ["devDependencies", "peerDependencies", "dependencies", "optionalDependencies"] as const) {
    const values = manifest[section];
    if (values === null || typeof values !== "object" || Array.isArray(values)) continue;
    for (const [name, range] of Object.entries(values)) {
      if (typeof range === "string") dependencies.set(name, { range, section });
    }
  }
  return dependencies;
}

interface Semver {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | null;
}

function parseSemver(value: string, allowPartial = false): Semver | null {
  const match = value.trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/u);
  if (!match?.[1] || (!allowPartial && (match[2] === undefined || match[3] === undefined))) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? 0),
    patch: Number(match[3] ?? 0),
    prerelease: match[4] ?? null,
  };
}

function compareSemver(left: Semver, right: Semver): number {
  for (const field of ["major", "minor", "patch"] as const) {
    if (left[field] !== right[field]) return left[field] < right[field] ? -1 : 1;
  }
  if (left.prerelease === right.prerelease) return 0;
  if (left.prerelease === null) return 1;
  if (right.prerelease === null) return -1;
  return compareUtf8(left.prerelease, right.prerelease);
}

/**
 * A deliberately conservative static semver check. `null` means the range
 * uses syntax we cannot prove safely; callers retain both local and external
 * candidates in that case instead of manufacturing an exact resolution.
 */
function semverSatisfies(versionValue: string, rangeValue: string): boolean | null {
  const version = parseSemver(versionValue);
  if (version === null) return null;
  const alternatives = rangeValue.split("||").map((item) => item.trim()).filter(Boolean);
  if (alternatives.length === 0) return null;
  let unknown = false;
  for (const alternative of alternatives) {
    const result = semverSatisfiesAlternative(version, alternative);
    if (result === true) return true;
    if (result === null) unknown = true;
  }
  return unknown ? null : false;
}

function semverSatisfiesAlternative(version: Semver, range: string): boolean | null {
  if (range === "*" || /^x$/iu.test(range)) return true;
  const wildcard = range.match(/^(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$/iu);
  if (wildcard?.[1]) {
    if (version.major !== Number(wildcard[1])) return false;
    if (wildcard[2] === undefined || /^(?:x|\*)$/iu.test(wildcard[2])) return true;
    if (version.minor !== Number(wildcard[2])) return false;
    if (wildcard[3] === undefined || /^(?:x|\*)$/iu.test(wildcard[3])) return true;
    return version.patch === Number(wildcard[3]) && version.prerelease === null;
  }
  const exact = range.match(/^=?\s*(v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/u)?.[1];
  if (exact) {
    const expected = parseSemver(exact);
    return expected === null ? null : compareSemver(version, expected) === 0;
  }
  const compatible = range.match(/^([~^])\s*(v?\d+\.\d+\.\d+)$/u);
  if (compatible?.[1] && compatible[2]) {
    if (version.prerelease !== null) return null;
    const lower = parseSemver(compatible[2], true);
    if (lower === null || compareSemver(version, lower) < 0) return false;
    const upper = compatible[1] === "~"
      ? { major: lower.major, minor: lower.minor + 1, patch: 0, prerelease: null }
      : lower.major > 0
        ? { major: lower.major + 1, minor: 0, patch: 0, prerelease: null }
        : lower.minor > 0
          ? { major: 0, minor: lower.minor + 1, patch: 0, prerelease: null }
          : { major: 0, minor: 0, patch: lower.patch + 1, prerelease: null };
    return compareSemver(version, upper) < 0;
  }
  const comparators = range.split(/\s+/u).filter(Boolean);
  if (comparators.length > 0 && comparators.every((item) => /^(?:>=|<=|>|<)=?v?\d+(?:\.\d+){0,2}$/u.test(item))) {
    if (version.prerelease !== null) return null;
    for (const comparator of comparators) {
      const match = comparator.match(/^(>=|<=|>|<)(v?\d+(?:\.\d+){0,2})$/u);
      if (!match?.[1] || !match[2]) return null;
      const expected = parseSemver(match[2], true);
      if (expected === null) return null;
      const compared = compareSemver(version, expected);
      if ((match[1] === ">=" && compared < 0) || (match[1] === ">" && compared <= 0)
        || (match[1] === "<=" && compared > 0) || (match[1] === "<" && compared >= 0)) return false;
    }
    return true;
  }
  return null;
}

function explicitLocalPackages(
  owner: PackageRecord,
  declared: string,
  namedLocal: PackageRecord[],
  allPackages: PackageRecord[],
): PackageRecord[] | null {
  if (declared.startsWith("workspace:")) return namedLocal;
  const reference = declared.match(/^(?:file|link|portal):(.+)$/u)?.[1];
  if (reference === undefined) return null;
  let decoded = reference;
  try {
    decoded = decodeURIComponent(reference);
  } catch {
    return [];
  }
  const target = path.resolve(owner.absolutePath, decoded);
  return allPackages.filter((record) => path.resolve(record.absolutePath) === target);
}

export function selectPackageInstallCandidates(
  workspace: Workspace,
  owner: PackageRecord,
  name: string,
  declared: string | null = owner.dependencies.get(name)?.range ?? null,
  excludedWorkspacePackageIds: ReadonlySet<string> = new Set(),
): PackageInstallSelection {
  const local = (workspace.packageByName.get(name) ?? [])
    .filter((record) => !excludedWorkspacePackageIds.has(record.id));
  if (declared !== null) {
    const explicit = explicitLocalPackages(owner, declared, local, workspace.packages);
    if (explicit !== null) {
      return {
        workspacePackages: explicit,
        externalInstances: [],
        precision: explicit.length === 1 ? "exact" : explicit.length > 1 ? "overapprox" : "heuristic",
        reason: explicit.length === 1 ? null : explicit.length > 1 ? "multiple_explicit_workspace_package_instances" : "explicit_local_package_target_not_found",
      };
    }
  }

  const locked = workspace.lockInstances.get(name) ?? [];
  const localMatches = declared === null
    ? local
    : local.filter((record) => semverSatisfies(record.version, declared) !== false);
  const lockedMatches = declared === null
    ? locked
    : locked.filter((instance) => semverSatisfies(instance.version, declared) !== false);
  const externalInstances = lockedMatches.length > 0
    ? lockedMatches
    : [{
      version: declared ?? "unknown",
      locator: `${workspace.manager}:${name}@${declared ?? "unknown"}`,
    }];
  const candidateCount = localMatches.length + externalInstances.length;
  const mixed = localMatches.length > 0 && externalInstances.length > 0;
  const uncertain = declared === null || (declared !== null && [
    ...localMatches.map((record) => semverSatisfies(record.version, declared)),
    ...externalInstances.map((instance) => semverSatisfies(instance.version, declared)),
  ].some((result) => result === null));
  return {
    workspacePackages: localMatches,
    externalInstances,
    precision: candidateCount > 1 ? "overapprox" : uncertain || lockedMatches.length === 0 ? "heuristic" : "exact",
    reason: mixed
      ? "workspace_and_external_package_candidates"
      : localMatches.length > 1 ? "multiple_workspace_package_instances"
      : externalInstances.length > 1 ? "multiple_locked_package_instances"
      : declared === null ? "package_declaration_not_found"
      : lockedMatches.length === 0 && externalInstances.length > 0 ? "version_from_manifest_range"
      : uncertain && localMatches.length > 0 ? "workspace_package_resolution_not_proven"
      : candidateCount === 0 ? "package_target_not_found"
      : null,
  };
}

async function loadManifest(root: string, file: string): Promise<{ manifest: Record<string, unknown> | null; issue?: WorkspaceIssue }> {
  const relative = normalizeRelative(path.relative(root, file));
  const source = await readUtf8(root, file);
  if (source === null) {
    return {
      manifest: null,
      issue: {
        code: "web.package_manifest_read_failed",
        path: relative,
        reason: "package manifest could not be read within the repository boundary",
      },
    };
  }
  try {
    const parsed: unknown = JSON.parse(source.replace(/^\uFEFF/u, ""));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("root value is not an object");
    return { manifest: parsed as Record<string, unknown> };
  } catch {
    return {
      manifest: null,
      issue: {
        code: "web.package_manifest_invalid",
        path: relative,
        reason: "package manifest is not a valid JSON object",
      },
    };
  }
}

function workspacePatterns(manifest: Record<string, unknown> | null, pnpmSource: string | null): string[] {
  const result: string[] = [];
  const workspaces = manifest?.workspaces;
  if (Array.isArray(workspaces)) {
    result.push(...workspaces.filter((item): item is string => typeof item === "string"));
  } else if (workspaces !== null && typeof workspaces === "object") {
    const packages = (workspaces as Record<string, unknown>).packages;
    if (Array.isArray(packages)) result.push(...packages.filter((item): item is string => typeof item === "string"));
  }
  if (pnpmSource !== null) {
    let inPackages = false;
    for (const line of pnpmSource.split(/\r?\n/u)) {
      if (/^packages\s*:/u.test(line)) {
        inPackages = true;
        continue;
      }
      if (inPackages && /^\S/u.test(line) && line.trim() !== "") break;
      const match = inPackages ? line.match(/^\s*-\s*['"]?([^'"#]+?)['"]?\s*$/u) : null;
      if (match?.[1]) result.push(match[1].trim());
    }
  }
  const expanded = result.flatMap((value) => {
    const match = value.match(/^(.*?)\{([^{}]+)\}(.*)$/u);
    return match?.[1] !== undefined && match[2] !== undefined && match[3] !== undefined
      ? match[2].split(",").map((choice) => `${match[1]}${choice.trim()}${match[3]}`)
      : [value];
  });
  // Workspace globs are an ordered rule list: a later negation must be able
  // to exclude a path included by an earlier positive rule. Keep declaration
  // order while removing exact duplicates.
  return [...new Set(expanded.map((value) => normalizeRelative(value.replace(/\/$/u, ""))))];
}

function globRegex(pattern: string): RegExp {
  let source = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index]!;
    if (character === "*") {
      if (pattern[index + 1] === "*") {
        source += ".*";
        index += 1;
      } else source += "[^/]*";
    } else if (character === "?") source += "[^/]";
    else source += character.replace(/[|\\{}()[\]^$+?.]/gu, "\\$&");
  }
  return new RegExp(`^${source}$`, "u");
}

function isWorkspacePath(relative: string, patterns: string[]): boolean {
  if (relative === ".") return true;
  if (patterns.length === 0) return false;
  let included = false;
  for (const pattern of patterns) {
    if (pattern.startsWith("!")) {
      if (globRegex(pattern.slice(1)).test(relative)) included = false;
    } else if (globRegex(pattern).test(relative)) included = true;
  }
  return included;
}

function normalizeRemote(value: string): string {
  const trimmed = value.trim().replace(/\.git$/u, "");
  const scp = trimmed.match(/^(?:[^@]+@)?([^:]+):(.+)$/u);
  if (scp?.[1] && scp[2] && !trimmed.includes("://")) return `${scp[1].toLowerCase()}/${scp[2]}`;
  try {
    const parsed = new URL(trimmed);
    return `${parsed.hostname.toLowerCase()}${parsed.pathname}`.replace(/\/$/u, "");
  } catch {
    return trimmed;
  }
}

async function repositoryIdentity(
  root: string,
  manifest: Record<string, unknown> | null,
  allFiles: string[],
): Promise<string> {
  const gitConfig = await readUtf8(root, path.join(root, ".git", "config"));
  if (gitConfig !== null) {
    const origin = gitConfig.match(/\[remote\s+"origin"\][\s\S]*?\n\s*url\s*=\s*([^\r\n]+)/u)?.[1];
    if (origin) return stableId("repository", { identity: normalizeRemote(origin) });
  }
  if (typeof manifest?.name === "string" && manifest.name.trim().length > 0) {
    return stableId("repository", { identity: `package:${manifest.name.trim()}` });
  }

  // A checkout directory name is deployment-local state and must never enter
  // stable IDs. When Git identity and a named root manifest are unavailable,
  // derive a conservative identity from repository-relative package manifest
  // locations and declared names. Malformed manifests still contribute their
  // relative path, so copying the same tree to another temporary directory is
  // deterministic without silently inventing an absolute identity.
  const manifests: Array<{ path: string; name: string | null }> = [];
  for (const file of allFiles
    .filter((candidate) => path.basename(candidate) === "package.json")
    .sort((left, right) => compareUtf8(
      normalizeRelative(path.relative(root, left)),
      normalizeRelative(path.relative(root, right)),
    ))) {
    const relative = normalizeRelative(path.relative(root, file));
    let parsed = relative === "package.json" ? manifest : null;
    if (parsed === null && relative !== "package.json") {
      const source = await readUtf8(root, file);
      try {
        const value: unknown = source === null ? null : JSON.parse(source.replace(/^\uFEFF/u, ""));
        if (value !== null && typeof value === "object" && !Array.isArray(value)) parsed = value as Record<string, unknown>;
      } catch {
        // The normal workspace loader records the malformed manifest. Its
        // relative path remains sufficient for the identity fallback.
      }
    }
    manifests.push({
      path: relative,
      name: typeof parsed?.name === "string" && parsed.name.trim().length > 0 ? parsed.name.trim() : null,
    });
  }
  return stableId("repository", { identity: "relative-package-manifests", manifests });
}

function detectManager(manifest: Record<string, unknown> | null, files: Set<string>): {
  manager: string;
  lockfile: string | null;
  ambiguousLockfiles: string[];
} {
  const declared = typeof manifest?.packageManager === "string" ? manifest.packageManager.split("@")[0] : null;
  const candidates: Array<[string, string[]]> = [
    ["pnpm", ["pnpm-lock.yaml"]],
    ["yarn", ["yarn.lock", ".pnp.data.json"]],
    ["bun", ["bun.lock", "bun.lockb"]],
    ["npm", ["npm-shrinkwrap.json", "package-lock.json"]],
  ];
  if (declared) {
    const match = candidates.find(([name]) => name === declared);
    const lockfile = match?.[1].find((file) => files.has(file));
    if (match) return { manager: match[0], lockfile: lockfile ?? null, ambiguousLockfiles: [] };
  }
  const present = candidates
    .map(([manager, lockfiles]) => ({ manager, lockfile: lockfiles.find((file) => files.has(file)) ?? null }))
    .filter((entry): entry is { manager: string; lockfile: string } => entry.lockfile !== null);
  if (present.length > 1) {
    return {
      manager: "ambiguous",
      lockfile: null,
      ambiguousLockfiles: present.map((entry) => entry.lockfile).sort(),
    };
  }
  if (present[0]) return { manager: present[0].manager, lockfile: present[0].lockfile, ambiguousLockfiles: [] };
  return { manager: "npm", lockfile: null, ambiguousLockfiles: [] };
}

function addLockInstance(result: Map<string, LockInstance[]>, name: string, version: string, locator: string): void {
  if (name.length === 0 || version.length === 0 || locator.length === 0) return;
  const instances = result.get(name) ?? [];
  if (!instances.some((instance) => instance.locator === locator)) instances.push({ version, locator });
  instances.sort((left, right) => compareUtf8(
    `${left.locator}\0${left.version}`,
    `${right.locator}\0${right.version}`,
  ));
  result.set(name, instances);
}

function collectJsonLockInstances(lock: Record<string, unknown>, result: Map<string, LockInstance[]>): void {
  const packages = lock.packages;
  if (packages !== null && typeof packages === "object" && !Array.isArray(packages)) {
    for (const [locator, data] of Object.entries(packages)) {
      if (!locator.includes("node_modules/") || data === null || typeof data !== "object" || Array.isArray(data)) continue;
      const name = locator.slice(locator.lastIndexOf("node_modules/") + "node_modules/".length);
      const version = (data as Record<string, unknown>).version;
      if (typeof version === "string") addLockInstance(result, name, version, `npm:${name}@${version}#${normalizeRelative(locator)}`);
    }
  }
  const dependencies = lock.dependencies;
  if (dependencies !== null && typeof dependencies === "object" && !Array.isArray(dependencies)) {
    for (const [name, data] of Object.entries(dependencies)) {
      const version = data !== null && typeof data === "object" && !Array.isArray(data)
        ? (data as Record<string, unknown>).version
        : null;
      // npm lockfile v2+ repeats its authoritative `packages` inventory in
      // `dependencies`; only use the latter as the v1 fallback so an install
      // instance is not duplicated under two different identities.
      if (typeof version === "string" && (result.get(name)?.length ?? 0) === 0) {
        addLockInstance(result, name, version, `npm:${name}@${version}`);
      }
    }
  }
}

function collectPnpInstances(data: Record<string, unknown>, result: Map<string, LockInstance[]>): void {
  const registry = data.packageRegistryData;
  if (!Array.isArray(registry)) return;
  for (const packageEntry of registry) {
    if (!Array.isArray(packageEntry) || typeof packageEntry[0] !== "string" || !Array.isArray(packageEntry[1])) continue;
    const name = packageEntry[0];
    for (const referenceEntry of packageEntry[1]) {
      if (!Array.isArray(referenceEntry) || typeof referenceEntry[0] !== "string") continue;
      const reference = referenceEntry[0];
      if (reference.startsWith("workspace:")) continue;
      const version = reference.replace(/^.*#npm:/u, "").replace(/^npm:/u, "");
      const locator = reference.startsWith("npm:") ? `yarn:${name}@${version}` : `yarn:${name}@${reference}`;
      addLockInstance(result, name, version, locator);
    }
  }
}

function unquoteLockScalar(value: string): string {
  const trimmed = value.trim();
  if (
    trimmed.length >= 2
    && ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'")))
  ) return trimmed.slice(1, -1);
  return trimmed;
}

function yarnLockScalar(line: string, key: string): string | null {
  const match = line.match(new RegExp(`^\\s+${key}(?::\\s*|\\s+)(.+?)\\s*$`, "u"));
  return match?.[1] === undefined ? null : unquoteLockScalar(match[1]);
}

function stableYarnIdentity(value: string, root: string): string {
  const canonicalRoot = path.resolve(root);
  let repositoryRelative = value.split(canonicalRoot).join(".");
  // The worker canonicalizes its root (for example /var -> /private/var on
  // macOS), while a lockfile may retain the lexical checkout path. Normalize
  // absolute file-like references through the repository directory name too.
  if (/(?:portal|link|file):/u.test(repositoryRelative)) {
    const basename = path.basename(canonicalRoot).replace(/[|\\{}()[\]^$+*?.-]/gu, "\\$&");
    repositoryRelative = repositoryRelative.replace(
      new RegExp(`(?:[A-Za-z]:)?[/\\\\](?:[^/\\\\]+[/\\\\])*${basename}(?=[/\\\\]|$)`, "gu"),
      ".",
    );
  }
  try {
    const parsed = new URL(repositoryRelative);
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return repositoryRelative;
  }
}

function canonicalYarnDescriptor(value: string, root: string): string {
  return value
    .split(",")
    .map((descriptor) => stableYarnIdentity(descriptor.trim(), root))
    .filter(Boolean)
    .sort()
    .join(",");
}

interface LockLoadResult {
  instances: Map<string, LockInstance[]>;
  invalidReason: string | null;
}

async function loadLockInstances(root: string, manager: string, lockfile: string | null): Promise<LockLoadResult> {
  const result = new Map<string, LockInstance[]>();
  if (lockfile === null) return { instances: result, invalidReason: null };
  const absolute = path.join(root, lockfile);
  if (lockfile.endsWith(".json")) {
    const source = await readUtf8(root, absolute);
    if (source === null) return { instances: result, invalidReason: "lock metadata could not be read within the repository boundary" };
    let value: Record<string, unknown> | null = null;
    try {
      const parsed: unknown = JSON.parse(source.replace(/^\uFEFF/u, ""));
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) value = parsed as Record<string, unknown>;
    } catch {
      // Reported below using the same stable diagnostic for all JSON locks.
    }
    if (value === null) return { instances: result, invalidReason: "lock metadata is not a valid JSON object" };
    collectJsonLockInstances(value, result);
    if (lockfile === ".pnp.data.json") {
      if (!Array.isArray(value.packageRegistryData)) {
        return { instances: result, invalidReason: ".pnp.data.json has no static packageRegistryData array" };
      }
      collectPnpInstances(value, result);
    }
    return { instances: result, invalidReason: null };
  }
  const source = await readUtf8(root, absolute);
  if (source === null) return { instances: result, invalidReason: "lockfile could not be read within the repository boundary" };
  if (lockfile.endsWith(".lockb")) return { instances: result, invalidReason: null };
  let structurallyRecognized = source.trim() === "";
  if (manager === "pnpm") {
    structurallyRecognized ||= /^lockfileVersion\s*:/mu.test(source);
    for (const line of source.split(/\r?\n/u)) {
      if (!/^\s{2,}\S/u.test(line) || !/:\s*$/u.test(line)) continue;
      const nativeLocator = unquoteLockScalar(line.trim().slice(0, -1)).replace(/^\//u, "");
      const parsed = nativeLocator.match(/^((?:@[^/()\s]+\/)?[^@()\s]+)@([^()\s]+)(?:\(.*\))?$/u);
      if (parsed?.[1] && parsed[2]) addLockInstance(result, parsed[1], parsed[2], `pnpm:${nativeLocator}`);
    }
  } else if (manager === "yarn") {
    structurallyRecognized ||= /^# yarn lockfile v1\s*$/mu.test(source)
      || /^__metadata:\s*$/mu.test(source)
      || /^\S.*:\s*$[\s\S]*?^\s+version(?::\s*|\s+)/mu.test(source);
    let descriptor = "";
    let names: string[] = [];
    let version = "";
    let resolution = "";
    let resolved = "";
    const flush = (): void => {
      if (!version) return;
      const nativeIdentity = resolution
        ? `resolution:${stableYarnIdentity(resolution, root)}`
        : resolved ? `resolved:${stableYarnIdentity(resolved, root)}` : `descriptor:${canonicalYarnDescriptor(descriptor, root)}`;
      for (const name of names) addLockInstance(result, name, version, `yarn:${name}@${version}#${nativeIdentity}`);
    };
    for (const line of source.split(/\r?\n/u)) {
      if (/^\S.*:\s*$/u.test(line)) {
        flush();
        descriptor = line.trim().slice(0, -1);
        version = "";
        resolution = "";
        resolved = "";
        // Workspace/link descriptors describe local packages, not registry
        // install instances. The manifest-level selector handles them using
        // the owning package's declaration.
        names = /@(?:workspace|link):/u.test(line)
          ? []
          : [...line.matchAll(/(?:^|,\s*)"?((?:@[^/]+\/)?[^@",\s]+)@/gu)].map((match) => match[1]!).filter(Boolean);
      } else {
        version = yarnLockScalar(line, "version") ?? version;
        resolution = yarnLockScalar(line, "resolution") ?? resolution;
        resolved = yarnLockScalar(line, "resolved") ?? resolved;
      }
    }
    flush();
  } else if (manager === "bun") {
    structurallyRecognized ||= /["']?lockfileVersion["']?\s*:/u.test(source) || /^\[packages\]\s*$/mu.test(source);
    for (const match of source.matchAll(/"((?:@[^/"\s]+\/)?[^@"\s]+)@([^"\s]+)"/gu)) {
      if (match[1] && match[2]) addLockInstance(result, match[1], match[2], `bun:${match[1]}@${match[2]}`);
    }
  }
  return {
    instances: result,
    invalidReason: structurallyRecognized ? null : `non-empty ${manager} lockfile has no recognized static structure`,
  };
}

export async function discoverWorkspace(root: string, allFiles: string[]): Promise<Workspace> {
  const relativeFiles = new Set(allFiles.map((file) => normalizeRelative(path.relative(root, file))));
  const issues: WorkspaceIssue[] = [];
  const rootManifestPath = path.join(root, "package.json");
  const rootLoad = relativeFiles.has("package.json") ? await loadManifest(root, rootManifestPath) : { manifest: null };
  const rootManifest = rootLoad.manifest;
  if (rootLoad.issue) issues.push(rootLoad.issue);
  const pnpmSource = await readUtf8(root, path.join(root, "pnpm-workspace.yaml"));
  const patterns = workspacePatterns(rootManifest, pnpmSource);
  const repository = await repositoryIdentity(root, rootManifest, allFiles);
  const { manager, lockfile, ambiguousLockfiles } = detectManager(rootManifest, relativeFiles);
  for (const ambiguous of ambiguousLockfiles) {
    issues.push({
      code: "web.package_manager_ambiguous",
      path: ambiguous,
      reason: `package manager is ambiguous across lockfiles: ${ambiguousLockfiles.join(", ")}; no lockfile was selected`,
    });
  }
  if (lockfile === "bun.lockb") {
    issues.push({
      code: "web.lockfile_unsupported",
      path: lockfile,
      reason: "binary bun.lockb cannot be interpreted by the safe static scanner; use Bun's text bun.lock format for exact package versions",
    });
  }
  const lockLoad = await loadLockInstances(root, manager, lockfile);
  const lockInstances = lockLoad.instances;
  if (lockfile !== null && lockLoad.invalidReason !== null) {
    issues.push({ code: "web.lockfile_invalid", path: lockfile, reason: lockLoad.invalidReason });
  }
  const knownLocks = new Map([
    ["pnpm-lock.yaml", "pnpm"],
    ["yarn.lock", "yarn"],
    [".pnp.data.json", "yarn"],
    ["bun.lock", "bun"],
    ["bun.lockb", "bun"],
    ["npm-shrinkwrap.json", "npm"],
    ["package-lock.json", "npm"],
  ]);
  for (const [candidate, candidateManager] of knownLocks) {
    if (!relativeFiles.has(candidate) || candidate === lockfile || ambiguousLockfiles.includes(candidate)) continue;
    if (candidate === ".pnp.data.json" && manager === "yarn") continue;
    if (candidate === "bun.lockb") {
      issues.push({
        code: "web.lockfile_unsupported",
        path: candidate,
        reason: "binary bun.lockb cannot be interpreted by the safe static scanner; use Bun's text bun.lock format for exact package versions",
      });
      continue;
    }
    const candidateLoad = await loadLockInstances(root, candidateManager, candidate);
    if (candidateLoad.invalidReason !== null) {
      issues.push({ code: "web.lockfile_invalid", path: candidate, reason: candidateLoad.invalidReason });
    }
  }
  if (manager === "yarn" && relativeFiles.has(".pnp.data.json") && lockfile !== ".pnp.data.json") {
    const pnpLoad = await loadLockInstances(root, "yarn", ".pnp.data.json");
    if (pnpLoad.invalidReason !== null) {
      issues.push({ code: "web.lockfile_invalid", path: ".pnp.data.json", reason: pnpLoad.invalidReason });
    } else {
      // PnP's registry is the authoritative installed-instance inventory.
      // Replace same-name lock catalog entries so one PnP reference does not
      // appear twice under both a descriptor and an installed reference.
      for (const [name, instances] of pnpLoad.instances) lockInstances.set(name, instances);
    }
  }
  const manifestCandidates = allFiles
    .filter((file) => path.basename(file) === "package.json")
    .map((file) => ({ file, relative: normalizeRelative(path.relative(root, path.dirname(file))) }));
  const manifests = manifestCandidates.filter(({ relative }) => isWorkspacePath(relative, patterns));
  const ignoredManifestPaths = manifestCandidates
    .filter(({ relative }) => !isWorkspacePath(relative, patterns))
    .map(({ file }) => normalizeRelative(path.relative(root, file)))
    .sort();
  if (rootManifest && !manifests.some(({ relative }) => relative === ".")) {
    manifests.unshift({ file: path.join(root, "package.json"), relative: "." });
  }
  const packages: PackageRecord[] = [];
  for (const { file, relative } of manifests.sort((left, right) => compareUtf8(left.relative, right.relative))) {
    const loaded = relative === "." ? { manifest: rootManifest } : await loadManifest(root, file);
    if (loaded.issue) issues.push(loaded.issue);
    const manifest = loaded.manifest;
    if (!manifest) continue;
    const name = stringValue(manifest.name, relative === "." ? "workspace-root" : path.basename(relative));
    const version = stringValue(manifest.version, "0.0.0-workspace");
    const locator = `${manager}:workspace:${name}@${version}#${relative}`;
    packages.push({
      absolutePath: path.dirname(file),
      relativePath: relative,
      manifestPath: normalizeRelative(path.relative(root, file)),
      manifest,
      name,
      version,
      locator,
      id: stableId("package", { repository, workspace: relative, manager, locator }),
      dependencies: dependenciesOf(manifest),
    });
  }
  if (packages.length === 0) {
    const name = "workspace-root";
    const locator = `synthetic:workspace:${name}@0.0.0#.`;
    packages.push({
      absolutePath: root,
      relativePath: ".",
      manifestPath: "package.json",
      manifest: {},
      name,
      version: "0.0.0",
      locator,
      id: stableId("package", { repository, workspace: ".", manager: "synthetic", locator }),
      dependencies: new Map(),
    });
  }
  const packageByName = new Map<string, PackageRecord[]>();
  for (const record of packages) packageByName.set(record.name, [...(packageByName.get(record.name) ?? []), record]);
  const workspaceId = stableId("workspace", { repository, root: "." });
  const workspaceNode: GraphNode = {
    id: workspaceId,
    kind: "workspace",
    locator: `workspace://${repository}`,
    display_name: stringValue(rootManifest?.name, "Web workspace"),
    properties: {
      repository_identity: repository,
      package_manager: manager,
      lockfile,
      safe_scan: true,
    },
  };
  return {
    root,
    repositoryIdentity: repository,
    rootManifest,
    packages,
    packageByName,
    manager,
    lockfile,
    lockInstances,
    workspaceNode,
    issues: issues.sort((left, right) => compareUtf8(`${left.path}\0${left.code}`, `${right.path}\0${right.code}`)),
    ignoredManifestPaths,
  };
}

export function packageProperties(record: PackageRecord, manager: string): Record<string, JsonValue> {
  return {
    name: record.name,
    version: record.version,
    package_manager: manager,
    workspace_path: record.relativePath,
    manifest_path: record.manifestPath,
    locator: record.locator,
    workspace: true,
  };
}

export function owningPackage(workspace: Workspace, absoluteFile: string): PackageRecord {
  return workspace.packages
    .filter((record) => absoluteFile === record.absolutePath || absoluteFile.startsWith(`${record.absolutePath}${path.sep}`))
    .sort((left, right) => right.absolutePath.length - left.absolutePath.length)[0] ?? workspace.packages[0]!;
}
