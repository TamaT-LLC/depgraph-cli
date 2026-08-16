import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const canary = path.join(repositoryRoot, "scripts/release-post-publish-canary.sh");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    ...options,
  });
  assert.equal(
    result.status,
    0,
    `${command} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  return result;
}

test("post-publish canary rejects mutable or malformed invocation", () => {
  const result = spawnSync(canary, [], { encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage:/);
});

test(
  "post-publish canary canonicalizes every packaged Agent host input",
  { skip: process.platform !== "linux" },
  async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "depgraph-release-canary-"));
    const publicRoot = path.join(temporary, "public");
    const repository = path.join(temporary, "repository");
    const output = path.join(temporary, "output");
    const staging = path.join(temporary, "staging");
    const packageName = "depgraph-1.2.3-x86_64-unknown-linux-gnu";
    const packageRoot = path.join(staging, packageName);
    const archiveName = `${packageName}.tar.gz`;
    const archive = path.join(publicRoot, archiveName);
    const evidence = path.join(temporary, "release-post-publish-evidence-v1.2.3.json");
    const requirement = path.join(
      publicRoot,
      "depgraph-compiler-pack-1.2.3-x86_64-unknown-linux-gnu.requirement.json",
    );
    const invocationLog = path.join(temporary, "invocations.log");

    await mkdir(path.join(packageRoot, "bin"), { recursive: true });
    await mkdir(publicRoot, { recursive: true });
    await mkdir(repository, { recursive: true });
    await writeFile(path.join(repository, "fixture.ts"), "export const fixture = true;\n");
    await writeFile(path.join(packageRoot, "release-manifest.json"), "{}\n");
    await writeFile(requirement, "{}\n");
    await writeFile(evidence, "closed evidence\n");

    const fakeDepgraph = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_DEPGRAPH_LOG"
agent_config=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    agent-config) agent_config=true; shift ;;
    --store|--root|--release-archive|--release-checksum|--release-evidence|--release-manifest|--compiler-pack-requirement)
      [[ "$2" = /* ]]
      shift 2
      ;;
    *) shift ;;
  esac
done
if [[ "$agent_config" == true ]]; then
  package_root="$(cd "$(dirname "$0")/.." && pwd)"
  printf '{"mcpServers":{"depgraph":{"command":"%s/bin/depgraph-mcp","args":[]}}}\\n' "$package_root"
else
  printf '{"scan":"ok"}\\n'
fi
`;
    const depgraph = path.join(packageRoot, "bin/depgraph");
    const depgraphMcp = path.join(packageRoot, "bin/depgraph-mcp");
    await writeFile(depgraph, fakeDepgraph);
    await writeFile(depgraphMcp, "#!/usr/bin/env bash\nexit 0\n");
    await chmod(depgraph, 0o755);
    await chmod(depgraphMcp, 0o755);

    run("tar", ["-czf", archive, "-C", staging, packageName]);
    const archiveDigest = createHash("sha256").update(await readFile(archive)).digest("hex");
    await writeFile(path.join(publicRoot, `${archiveName}.sha256`), `${archiveDigest}  ${archiveName}\n`);
    const evidenceDigest = createHash("sha256").update(await readFile(evidence)).digest("hex");

    run(
      canary,
      ["v1.2.3", publicRoot, evidence, evidenceDigest, repository, output],
      { env: { ...process.env, FAKE_DEPGRAPH_LOG: invocationLog } },
    );

    const configuration = JSON.parse(await readFile(path.join(output, "claude-desktop.json"), "utf8"));
    assert.equal(path.isAbsolute(configuration.mcpServers.depgraph.command), true);
    const invocations = await readFile(invocationLog, "utf8");
    for (const flag of [
      "--store",
      "--root",
      "--release-archive",
      "--release-checksum",
      "--release-evidence",
      "--release-manifest",
      "--compiler-pack-requirement",
    ]) {
      assert.match(invocations, new RegExp(`${flag} /`));
    }
  },
);
