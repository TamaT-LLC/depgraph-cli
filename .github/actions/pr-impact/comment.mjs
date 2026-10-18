// Create or update the single depgraph impact comment on a pull request.
// The comment is identified by the hidden marker and by its author, so a
// comment that merely quotes the marker is never overwritten.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { COMMENT_MARKER } from "./render.mjs";

export const DEFAULT_AUTHOR_LOGIN = "github-actions[bot]";
const DEFAULT_API_URL = "https://api.github.com";
const PER_PAGE = 100;
const MAX_PAGES = 50;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const PR_NUMBER_PATTERN = /^[1-9][0-9]{0,9}$/;

export function isOwnComment(comment, { authorLogin } = {}) {
  if (typeof comment?.body !== "string" || !comment.body.includes(COMMENT_MARKER)) return false;
  const user = comment.user ?? {};
  if (authorLogin && user.login === authorLogin) return true;
  return user.type === "Bot" && user.login === DEFAULT_AUTHOR_LOGIN;
}

function nextLink(linkHeader) {
  if (!linkHeader) return undefined;
  for (const part of linkHeader.split(",")) {
    const match = part.match(/<([^>]+)>\s*;\s*rel="([^"]+)"/);
    if (match && match[2].split(/\s+/).includes("next")) return match[1];
  }
  return undefined;
}

async function request(fetchImpl, url, { token, method = "GET", body } = {}) {
  const headers = {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "x-github-api-version": "2022-11-28",
    "user-agent": "depgraph-pr-impact",
  };
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetchImpl(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`GitHub API ${method} ${new URL(url).pathname} failed with ${response.status}: ${text.slice(0, 200)}`);
  }
  return response;
}

function validateTarget({ repository, prNumber }) {
  const number = typeof prNumber === "number" ? String(prNumber) : prNumber;
  if (typeof number !== "string" || !PR_NUMBER_PATTERN.test(number)) {
    throw new Error(`pull request number is invalid: ${JSON.stringify(prNumber)}`);
  }
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository) || repository.split("/").some((part) => /^\.+$/.test(part))) {
    throw new Error(`repository is invalid: ${JSON.stringify(repository)}`);
  }
  return number;
}

export async function upsertComment({
  token,
  repository,
  prNumber,
  body,
  apiUrl = DEFAULT_API_URL,
  authorLogin,
  fetch: fetchImpl = globalThis.fetch,
}) {
  const number = validateTarget({ repository, prNumber });
  if (!token) throw new Error("a GitHub token is required to post the comment");
  const api = new URL(apiUrl);
  const base = api.href.replace(/\/$/, "");

  let url = `${base}/repos/${repository}/issues/${number}/comments?per_page=${PER_PAGE}&page=1`;
  let existing;
  for (let page = 0; url && page < MAX_PAGES; page += 1) {
    if (new URL(url).origin !== api.origin) throw new Error("refusing to follow a pagination link to another origin");
    const response = await request(fetchImpl, url, { token });
    const comments = await response.json();
    existing = comments.find((comment) => isOwnComment(comment, { authorLogin }));
    if (existing) break;
    url = nextLink(response.headers.get("link"));
  }

  if (existing) {
    const id = Number(existing.id);
    if (!Number.isSafeInteger(id) || id <= 0) throw new Error("existing comment id is invalid");
    const response = await request(fetchImpl, `${base}/repos/${repository}/issues/comments/${id}`, {
      token,
      method: "PATCH",
      body: { body },
    });
    const updated = await response.json();
    return { action: "updated", id, url: updated.html_url };
  }
  const response = await request(fetchImpl, `${base}/repos/${repository}/issues/${number}/comments`, {
    token,
    method: "POST",
    body: { body },
  });
  const created = await response.json();
  return { action: "created", id: created.id, url: created.html_url };
}

async function main() {
  const env = process.env;
  if (!env.COMMENT_PATH) throw new Error("COMMENT_PATH is required");
  const result = await upsertComment({
    token: env.GITHUB_TOKEN,
    repository: env.GITHUB_REPOSITORY,
    prNumber: env.PR_NUMBER,
    body: readFileSync(env.COMMENT_PATH, "utf8"),
    apiUrl: env.GITHUB_API_URL || DEFAULT_API_URL,
    authorLogin: env.COMMENT_AUTHOR || undefined,
  });
  console.log(`depgraph pr-impact: ${result.action} comment ${result.id}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    console.error(`depgraph pr-impact comment: ${error.message}`);
    process.exit(1);
  });
}
