// Render report.json (from collect.mjs) into the Markdown body of the pull
// request comment. Every value that came from the analysed repository is
// escaped: display names, paths, and messages are attacker-controlled on a
// pull request, so none of them may open HTML, links, code spans, or mentions.

import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const COMMENT_MARKER = "<!-- depgraph-pr-impact -->";
export const DEFAULT_MAX_LENGTH = 60000;

const TABLE_ROW_LIMIT = 100;
const PATH_STEP_LIMIT = 20;
const EVIDENCE_PER_STEP_LIMIT = 3;
const LIST_LIMIT = 100;
const REACHED_FROM_LIMIT = 3;
const TRUNCATION_RESERVE = 1200;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;

const ENTITY = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "|": "&#124;",
  "`": "&#96;",
  "[": "&#91;",
  "]": "&#93;",
  "*": "&#42;",
  _: "&#95;",
  "~": "&#126;",
  "\\": "&#92;",
  "@": "&#64;",
  "#": "&#35;",
  "!": "&#33;",
};

/** Escape text for use in Markdown prose, table cells, and HTML summaries. */
export function escapeMarkdown(value) {
  return String(value ?? "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/[&<>"|`[\]*_~\\@#!]/g, (character) => ENTITY[character]);
}

const IDENTIFIER_PATTERN = /^[A-Za-z0-9_.:-]+$/;

/** Show a CLI enum value (edge or node kind) as code when it is a plain identifier. */
function identifier(value) {
  const text = String(value ?? "unknown");
  return IDENTIFIER_PATTERN.test(text) ? `\`${text}\`` : escapeMarkdown(text);
}

function encodePathSegment(segment) {
  return encodeURIComponent(segment).replace(/[()'!*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Link to a line range of a file at the pull request head, or null when unsafe. */
export function blobUrl({ repository, headSha, path, startLine, endLine }) {
  if (!REPOSITORY_PATTERN.test(repository ?? "") || !SHA_PATTERN.test(headSha ?? "")) return null;
  if (typeof path !== "string" || path.length === 0 || path.startsWith("/") || path.includes("\\")) return null;
  const segments = path.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) return null;
  if (!Number.isInteger(startLine) || startLine < 1) return null;
  const anchor = Number.isInteger(endLine) && endLine > startLine ? `#L${startLine}-L${endLine}` : `#L${startLine}`;
  return `https://github.com/${repository}/blob/${headSha}/${segments.map(encodePathSegment).join("/")}${anchor}`;
}

function shortSha(sha) {
  return typeof sha === "string" && SHA_PATTERN.test(sha) ? sha.slice(0, 7) : "unknown";
}

function scanLabel(scan) {
  switch (scan.status) {
    case "ok":
      return scan.strict ? "scan 成功（strict: 違反なし）" : "scan 成功";
    case "policy_violation":
      return "scan 完了（strict: ポリシー違反あり）";
    case "partial":
      return "scan 部分結果";
    default:
      return `scan 失敗（exit ${escapeMarkdown(scan.exit_code)}）`;
  }
}

function scanNotices(report) {
  const { scan } = report;
  const lines = [];
  const detail = scan.message ? `: ${escapeMarkdown(scan.message)}` : "";
  if (scan.status === "failed") {
    lines.push("> [!CAUTION]", `> scan が失敗しました（exit ${escapeMarkdown(scan.exit_code)}）${detail}`, "> 影響範囲は計算していません。");
  } else if (scan.status === "partial") {
    lines.push(
      "> [!WARNING]",
      `> 一部のワーカーが失敗したため、scan は部分結果です（exit ${escapeMarkdown(scan.exit_code)}）${detail}`,
      "> 以下の影響範囲は解析できた部分だけから計算しており、漏れがありえます。",
    );
  } else if (scan.status === "policy_violation") {
    lines.push("> [!WARNING]", `> strict モードの scan でポリシー違反が検出されました（exit 1）${detail}`);
  }
  if (report.incomplete && scan.status !== "failed" && scan.status !== "partial") {
    if (lines.length > 0) lines.push("");
    lines.push("> [!NOTE]", "> 一部のファイルは解析できなかったか上限で打ち切られたため、影響範囲は完全ではありません。");
  }
  return lines;
}

function summaryLine(report) {
  const { totals } = report;
  return [
    `変更ファイル ${totals.changed} 件`,
    `影響ルート ${totals.routes} 件`,
    `影響パッケージ ${totals.packages} 件`,
    `その他ノード ${totals.others} 件`,
    scanLabel(report.scan),
  ].join(" / ");
}

function reachedFromCell(paths) {
  const shown = paths.slice(0, REACHED_FROM_LIMIT).map(escapeMarkdown).join(", ");
  const rest = paths.length - REACHED_FROM_LIMIT;
  return rest > 0 ? `${shown} ほか ${rest} 件` : shown;
}

function impactTable(title, header, entries) {
  if (entries.length === 0) return [];
  const lines = [`#### ${title}（${entries.length} 件）`, "", `| ${header} | 深さ | 起点の変更ファイル |`, "| --- | ---: | --- |"];
  for (const entry of entries.slice(0, TABLE_ROW_LIMIT)) {
    lines.push(`| ${escapeMarkdown(entry.display_name)} | ${entry.depth} | ${reachedFromCell(entry.reached_from)} |`);
  }
  const rest = entries.length - TABLE_ROW_LIMIT;
  if (rest > 0) lines.push("", `表示しきれない ${rest} 件は省略しました。全件は report.json を参照してください。`);
  lines.push("");
  return lines;
}

function evidenceLink(evidence, context) {
  const repoPath = `${context.pathPrefix}${evidence.path ?? ""}`;
  const start = evidence.start_line;
  const end = evidence.end_line;
  const label = Number.isInteger(start) ? `${repoPath}:${start}` : repoPath;
  const url = blobUrl({ repository: context.repository, headSha: context.headSha, path: repoPath, startLine: start, endLine: end });
  return url ? `[${escapeMarkdown(label)}](${url})` : escapeMarkdown(label);
}

// Several extractors can attest the same source range; the reader only needs
// each location once.
function uniqueEvidence(evidence) {
  const seen = new Set();
  return evidence.filter((item) => {
    const key = `${item.path}\0${item.start_line}\0${item.end_line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function evidenceBlock(entry, context) {
  const kindLabel = entry.kind === "route" ? "ルート" : entry.kind === "package_instance" ? "パッケージ" : escapeMarkdown(entry.kind);
  const lines = [
    "<details>",
    `<summary>${kindLabel} ${escapeMarkdown(entry.display_name)}（深さ ${entry.depth}）</summary>`,
    "",
    "影響ノードから変更ファイルへ向かう依存の経路:",
    "",
  ];
  const steps = entry.dependency_path ?? [];
  if (steps.length === 0) lines.push("- 経路の根拠は記録されていません。");
  steps.slice(0, PATH_STEP_LIMIT).forEach((stepEntry, index) => {
    const evidence = uniqueEvidence(stepEntry.evidence ?? []).slice(0, EVIDENCE_PER_STEP_LIMIT);
    const where = evidence.length > 0 ? evidence.map((item) => evidenceLink(item, context)).join(", ") : "根拠の位置なし";
    lines.push(`${index + 1}. ${identifier(stepEntry.edge?.kind)} — ${where}`);
  });
  if (steps.length > PATH_STEP_LIMIT) lines.push(`- ほか ${steps.length - PATH_STEP_LIMIT} ステップは省略しました。`);
  lines.push("", "</details>", "");
  return lines.join("\n");
}

function unmappedDetail(message) {
  const detail = String(message ?? "").replace(/^no graph node for this path\s*/, "");
  return detail ? `: ${escapeMarkdown(detail)}` : "";
}

function fileProblemLines(report) {
  const lines = [];
  for (const file of report.changed_files) {
    const path = escapeMarkdown(file.path);
    switch (file.status) {
      case "unmapped":
        lines.push(`- ${path} — グラフ上に対応するノードがありません${unmappedDetail(file.message)}`);
        break;
      case "error":
        lines.push(`- ${path} — エラー（exit ${escapeMarkdown(file.exit_code)}）: ${escapeMarkdown(file.message)}`);
        break;
      case "deleted":
        lines.push(`- ${path} — 削除されたファイル（影響範囲は計算していません）`);
        break;
      case "not_analyzed":
        lines.push(`- ${path} — scan 失敗のため未解析`);
        break;
      default:
        if (file.complete === false) lines.push(`- ${path} — 上限に達したため結果が不完全です`);
    }
  }
  const shown = lines.slice(0, LIST_LIMIT);
  if (lines.length > LIST_LIMIT) shown.push(`- ほか ${lines.length - LIST_LIMIT} 件は省略しました。`);
  if (report.skipped.count > 0) {
    const names = report.skipped.paths.slice(0, 10).map(escapeMarkdown).join(", ");
    shown.push(`- max-files の上限を超えたため ${report.skipped.count} 件のファイルは解析していません（${names}${report.skipped.count > 10 ? " ほか" : ""}）`);
  }
  return shown;
}

function otherKindsLine(others) {
  if (others.length === 0) return [];
  const counts = new Map();
  for (const entry of others) counts.set(entry.kind, (counts.get(entry.kind) ?? 0) + 1);
  const parts = [...counts.entries()].sort(([left], [right]) => (left < right ? -1 : 1)).map(([kind, count]) => `${identifier(kind)} ${count}`);
  return [`その他の影響ノードの内訳: ${parts.join(", ")}`, ""];
}

function footer(report) {
  return [
    "---",
    `<sub>depgraph ${escapeMarkdown(report.depgraph_version)} による静的解析の結果です。プロジェクトのコードは実行していません。` +
      ` base ${shortSha(report.merge_base)} → head ${shortSha(report.head_sha)}</sub>`,
    "",
  ].join("\n");
}

function balanceDetails(text) {
  const opened = (text.match(/<details>/g) ?? []).length;
  const closed = (text.match(/<\/details>/g) ?? []).length;
  return opened > closed ? `${text}\n\n${"</details>\n".repeat(opened - closed)}` : text;
}

/** Produce the comment body, never longer than maxLength characters. */
export function renderComment(report, { repository, maxLength = DEFAULT_MAX_LENGTH } = {}) {
  const context = { repository, headSha: report.head_sha, pathPrefix: report.path_prefix ?? "" };
  const routes = report.impacted.filter((entry) => entry.kind === "route");
  const packages = report.impacted.filter((entry) => entry.kind === "package_instance");
  const others = report.impacted.filter((entry) => entry.kind !== "route" && entry.kind !== "package_instance");

  const head = [COMMENT_MARKER, "### depgraph: この PR の影響範囲", "", summaryLine(report), ""];
  const notices = scanNotices(report);
  if (notices.length > 0) head.push(...notices, "");
  if (report.scan.status !== "failed") {
    if (report.impacted.length === 0) {
      head.push("影響を受けるノードは見つかりませんでした。", "");
    } else if (routes.length === 0 && packages.length === 0) {
      head.push("ルートとパッケージへの影響は見つかりませんでした。", "");
    }
  }
  head.push(...impactTable("影響ルート", "ルート", routes));
  head.push(...impactTable("影響パッケージ", "パッケージ", packages));
  head.push(...otherKindsLine(others));

  const tail = [];
  const problems = fileProblemLines(report);
  if (problems.length > 0) {
    tail.push(`<details>`, `<summary>解析できなかったファイル・対象外のファイル（${problems.length} 件）</summary>`, "", ...problems, "", "</details>", "");
  }
  const tailText = tail.join("\n");
  const footerText = footer(report);

  let body = head.join("\n");
  const budget = maxLength - tailText.length - footerText.length - TRUNCATION_RESERVE;
  const detailed = [...routes.slice(0, TABLE_ROW_LIMIT), ...packages.slice(0, TABLE_ROW_LIMIT)];
  let omitted = 0;
  if (detailed.length > 0 && body.length < budget) body += "\n#### 根拠\n\n";
  for (const entry of detailed) {
    const block = evidenceBlock(entry, context);
    if (body.length + block.length > budget) {
      omitted += 1;
      continue;
    }
    body += block;
  }
  if (omitted > 0) body += `\n根拠 ${omitted} 件はコメントの長さの上限のため省略しました。全件は report.json を参照してください。\n`;

  let result = `${body}\n${tailText}\n${footerText}`;
  if (result.length > maxLength) {
    const notice = "\n\n（コメントの長さの上限を超えたため、ここで切り詰めました。全件は report.json を参照してください。）\n\n";
    const keep = maxLength - footerText.length - notice.length - TRUNCATION_RESERVE;
    let cut = result.slice(0, Math.max(keep, COMMENT_MARKER.length));
    const newline = cut.lastIndexOf("\n");
    if (newline > COMMENT_MARKER.length) cut = cut.slice(0, newline);
    result = `${balanceDetails(cut)}${notice}${footerText}`;
  }
  return result;
}

function main() {
  const reportPath = process.env.REPORT_PATH;
  const commentPath = process.env.COMMENT_PATH;
  if (!reportPath || !commentPath) throw new Error("REPORT_PATH and COMMENT_PATH are required");
  const report = JSON.parse(readFileSync(reportPath, "utf8"));
  const body = renderComment(report, { repository: process.env.GITHUB_REPOSITORY });
  writeFileSync(commentPath, body);
  console.log(`depgraph pr-impact: wrote ${body.length} characters to the comment body`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    main();
  } catch (error) {
    console.error(`depgraph pr-impact render: ${error.message}`);
    process.exit(1);
  }
}
