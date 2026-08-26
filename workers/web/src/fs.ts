import type { Dirent, Stats } from "node:fs";
import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { compareUtf8 } from "./types";

const REPOSITORY_INVENTORY_CONTRACT_VERSION = "depgraph-repository-file-inventory-v1";
const MAX_REPOSITORY_INVENTORY_BYTES = 64 * 1024 * 1024;
const MAX_REPOSITORY_INVENTORY_FILES = 1_000_000;

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".next",
  ".turbo",
  ".cache",
  ".output",
  "coverage",
  "dist",
  "build",
  "node_modules",
  "target",
]);

const INVENTORY_FORBIDDEN_DIRECTORIES = new Set([
  ".astro",
  ".cache",
  ".depgraph",
  ".git",
  ".hg",
  ".next",
  ".output",
  ".svn",
  ".turbo",
  "node_modules",
  "target",
]);

export interface FileInventoryIssue {
  path: string;
  reason: "out_of_root_symlink" | "symlink_not_followed" | "unreadable_path";
  detail: string;
}

export interface FileInventory {
  files: string[];
  issues: FileInventoryIssue[];
}

export const WEB_SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".astro",
  ".md",
  ".mdx",
  ".html",
]);

const WEB_RESOURCE_EXTENSIONS = new Set([
  ".avif", ".bmp", ".css", ".gif", ".ico", ".jpeg", ".jpg", ".json", ".less",
  ".png", ".sass", ".scss", ".svg", ".tiff", ".ttf", ".webp", ".woff", ".woff2",
  ".yaml", ".yml",
]);

function isRelevantFileName(name: string): boolean {
  return WEB_SOURCE_EXTENSIONS.has(path.extname(name).toLowerCase())
    || WEB_RESOURCE_EXTENSIONS.has(path.extname(name).toLowerCase())
    || /^(?:package\.json|pnpm-workspace\.yaml|pnpm-lock\.yaml|yarn\.lock|bun\.lock|bun\.lockb|package-lock\.json|npm-shrinkwrap\.json|\.pnp\.data\.json)$/u.test(name)
    || /^(?:tsconfig|jsconfig)(?:\.[^.]+)*\.json$/u.test(name)
    || /^(?:next|astro|vite|tanstack|router|webpack|rollup)\.config\./u.test(name)
    || /^routeTree\.gen\./u.test(name);
}

export function normalizeRelative(value: string): string {
  const normalized = value.replaceAll("\\", "/").replace(/^\.\//u, "");
  return normalized === "" ? "." : normalized;
}

export function isWithinRoot(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/**
 * Resolve a path before it is read and prove that its target is still inside
 * the canonical scan root. This is intentionally used for direct reads that
 * are not sourced from walkFiles (workspace metadata, config, and generated
 * route files), because those paths may themselves be symbolic links.
 */
export async function resolveWithinRoot(root: string, candidate: string): Promise<string | null> {
  try {
    let canonicalRoot = path.resolve(root);
    const resolved = await realpath(candidate);
    if (!isWithinRoot(canonicalRoot, resolved)) canonicalRoot = await realpath(canonicalRoot);
    return isWithinRoot(canonicalRoot, resolved) ? resolved : null;
  } catch {
    return null;
  }
}

export async function readUtf8(root: string, file: string): Promise<string | null> {
  const resolved = await resolveWithinRoot(root, file);
  if (resolved === null) return null;
  try {
    return await readFile(resolved, "utf8");
  } catch {
    return null;
  }
}

export async function readJson(root: string, file: string): Promise<Record<string, unknown> | null> {
  const source = await readUtf8(root, file);
  if (source === null) return null;
  try {
    const parsed: unknown = JSON.parse(source.replace(/^\uFEFF/u, ""));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export async function inventoryFiles(root: string): Promise<FileInventory> {
  const canonicalRoot = await realpath(root);
  const result: string[] = [];
  const issues: FileInventoryIssue[] = [];
  function issue(absolute: string, reason: FileInventoryIssue["reason"], detail: string): void {
    issues.push({ path: normalizeRelative(path.relative(canonicalRoot, absolute)), reason, detail });
  }
  async function visit(directory: string): Promise<void> {
    const resolvedDirectory = await resolveWithinRoot(canonicalRoot, directory);
    if (resolvedDirectory === null) {
      issue(directory, "unreadable_path", "directory could not be resolved within the repository boundary");
      return;
    }
    let entries: Dirent[];
    try {
      entries = await readdir(resolvedDirectory, { withFileTypes: true });
    } catch {
      issue(directory, "unreadable_path", "directory could not be read during source inventory");
      return;
    }
    entries.sort((left, right) => compareUtf8(left.name, right.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (IGNORED_DIRECTORIES.has(entry.name)) continue;
      if (entry.isSymbolicLink()) {
        if (!isRelevantFileName(entry.name)) {
          try {
            const target = await realpath(absolute);
            if ((await stat(target)).isDirectory()) {
              const inside = isWithinRoot(canonicalRoot, target);
              issue(
                absolute,
                inside ? "symlink_not_followed" : "out_of_root_symlink",
                inside
                  ? "symbolic-link directory was not traversed in safe mode"
                  : "symbolic-link directory resolves outside the repository boundary",
              );
            }
          } catch {
            // Broken non-source links are not part of the Web inventory.
          }
          continue;
        }
        try {
          const target = await realpath(absolute);
          issue(
            absolute,
            isWithinRoot(canonicalRoot, target) ? "symlink_not_followed" : "out_of_root_symlink",
            isWithinRoot(canonicalRoot, target)
              ? "symbolic-link source was not read in safe mode"
              : "symbolic-link source resolves outside the repository boundary",
          );
        } catch {
          issue(absolute, "unreadable_path", "symbolic-link source target could not be read");
        }
        continue;
      }
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (entry.isFile()) {
        if (await resolveWithinRoot(canonicalRoot, absolute) !== null) result.push(absolute);
        else if (isRelevantFileName(entry.name)) issue(absolute, "unreadable_path", "source could not be resolved within the repository boundary");
      }
    }
  }
  await visit(root);
  issues.sort((left, right) => compareUtf8(
    `${left.path}\0${left.reason}\0${left.detail}`,
    `${right.path}\0${right.reason}\0${right.detail}`,
  ));
  return { files: result, issues };
}

export async function inventoryFilesFromManifest(
  root: string,
  inventoryFile: string,
): Promise<FileInventory> {
  const inventoryStat = await stat(inventoryFile);
  if (!inventoryStat.isFile() || inventoryStat.size > MAX_REPOSITORY_INVENTORY_BYTES) {
    throw new Error("repository inventory file exceeds its closed byte limit");
  }
  const parsed: unknown = JSON.parse(await readFile(inventoryFile, "utf8"));
  if (
    parsed === null
    || typeof parsed !== "object"
    || Array.isArray(parsed)
    || Object.keys(parsed).sort(compareUtf8).join("\0") !== "contract_version\0paths"
    || (parsed as { contract_version?: unknown }).contract_version !== REPOSITORY_INVENTORY_CONTRACT_VERSION
    || !Array.isArray((parsed as { paths?: unknown }).paths)
  ) {
    throw new Error("repository inventory file does not satisfy its closed contract");
  }
  const rawPaths = (parsed as { paths: unknown[] }).paths;
  if (rawPaths.length > MAX_REPOSITORY_INVENTORY_FILES) {
    throw new Error("repository inventory exceeds its closed file-count limit");
  }
  const relativePaths: string[] = [];
  const seen = new Set<string>();
  for (const value of rawPaths) {
    if (
      typeof value !== "string"
      || value.length === 0
      || value.includes("\\")
      || /[\u0000-\u001f\u007f]/u.test(value)
      || path.posix.isAbsolute(value)
      || path.posix.normalize(value) !== value
      || value.split("/").some((component) => component === "" || component === "." || component === "..")
      || value.split("/").some((component) => INVENTORY_FORBIDDEN_DIRECTORIES.has(component))
      || seen.has(value)
    ) {
      throw new Error("repository inventory contains a non-canonical or duplicate path");
    }
    seen.add(value);
    relativePaths.push(value);
  }
  relativePaths.sort(compareUtf8);

  const canonicalRoot = await realpath(root);
  const files: string[] = [];
  const issues: FileInventoryIssue[] = [];
  for (const relative of relativePaths) {
    const absolute = path.join(canonicalRoot, ...relative.split("/"));
    let metadata: Stats;
    try {
      metadata = await lstat(absolute);
    } catch {
      // A tracked file may disappear between Git inventory and worker launch.
      continue;
    }
    if (metadata.isSymbolicLink()) {
      if (!isRelevantFileName(path.basename(relative))) continue;
      try {
        const target = await realpath(absolute);
        const inside = isWithinRoot(canonicalRoot, target);
        issues.push({
          path: relative,
          reason: inside ? "symlink_not_followed" : "out_of_root_symlink",
          detail: inside
            ? "symbolic-link source was not read in safe mode"
            : "symbolic-link source resolves outside the repository boundary",
        });
      } catch {
        issues.push({
          path: relative,
          reason: "unreadable_path",
          detail: "symbolic-link source target could not be read",
        });
      }
    } else if (metadata.isFile()) {
      const resolved = await resolveWithinRoot(canonicalRoot, absolute);
      if (resolved !== null) files.push(resolved);
      else if (isRelevantFileName(path.basename(relative))) {
        issues.push({
          path: relative,
          reason: "unreadable_path",
          detail: "source could not be resolved within the repository boundary",
        });
      }
    }
  }
  issues.sort((left, right) => compareUtf8(
    `${left.path}\0${left.reason}\0${left.detail}`,
    `${right.path}\0${right.reason}\0${right.detail}`,
  ));
  return { files, issues };
}

export async function walkFiles(root: string): Promise<string[]> {
  return (await inventoryFiles(root)).files;
}

export async function isFile(root: string, file: string): Promise<boolean> {
  const resolved = await resolveWithinRoot(root, file);
  if (resolved === null) return false;
  try {
    return (await stat(resolved)).isFile();
  } catch {
    return false;
  }
}
