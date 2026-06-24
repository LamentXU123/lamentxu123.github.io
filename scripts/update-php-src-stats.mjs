import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const owner = "php";
const repo = "php-src";
const author = "LamentXU123";
const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, "php-src-stats.json");
const commitAuthors = [
  "LamentXU123",
  "Weilin Du",
  "lamentxu",
  "weilindu@php.net",
  "108666168+LamentXU123@users.noreply.github.com",
  "1372449351@qq.com"
];
const refQueries = (process.env.PHP_SRC_STATS_REFS || "")
  .split(",")
  .map((ref) => ref.trim())
  .filter(Boolean);

if (!token) {
  throw new Error("GITHUB_TOKEN or GH_TOKEN is required.");
}

const headers = {
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "User-Agent": "lamentxu-php-src-stats"
};

async function restJson(url) {
  const response = await fetch(url, { headers });
  const body = await response.json();

  if (!response.ok) {
    throw new Error(`GitHub REST failed: ${JSON.stringify(body)}`);
  }

  return {
    body,
    link: response.headers.get("link") || ""
  };
}

function getNextUrl(link) {
  if (!link) {
    return null;
  }

  for (const part of link.split(",")) {
    const [urlPart, relPart] = part.split(";");
    if (relPart && relPart.includes('rel="next"')) {
      return urlPart.trim().replace(/^<|>$/g, "");
    }
  }

  return null;
}

async function fetchCommitsForAuthor(commitAuthor, ref) {
  const params = new URLSearchParams({
    author: commitAuthor,
    per_page: "100"
  });

  if (ref) {
    params.set("sha", ref);
  }

  let url = `https://api.github.com/repos/${owner}/${repo}/commits?${params}`;
  const commits = [];

  while (url) {
    const { body, link } = await restJson(url);
    commits.push(...(body || []));
    url = getNextUrl(link);
  }

  return commits;
}

async function fetchAuthoredCommits() {
  const refs = refQueries.length ? refQueries : [null];
  const commits = new Map();

  for (const ref of refs) {
    for (const commitAuthor of commitAuthors) {
      const results = await fetchCommitsForAuthor(commitAuthor, ref);

      for (const commit of results) {
        if (!commits.has(commit.sha)) {
          commits.set(commit.sha, {
            sha: commit.sha,
            url: commit.url,
            author: commitAuthor,
            ref
          });
        }
      }
    }
  }

  return Array.from(commits.values());
}

async function fetchCommitStats(commit) {
  const { body } = await restJson(commit.url);
  return body.stats || { additions: 0, deletions: 0 };
}

const commits = await fetchAuthoredCommits();
let additions = 0;
let deletions = 0;
let completed = 0;

for (const commit of commits) {
  const commitStats = await fetchCommitStats(commit);
  additions += commitStats.additions || 0;
  deletions += commitStats.deletions || 0;
  completed++;
  process.stdout.write(`\rFetched php-src commit stats ${completed}/${commits.length}`);
}

if (commits.length) {
  process.stdout.write("\n");
}

const stats = {
  owner,
  repo,
  author,
  authors: commitAuthors,
  method: "commits",
  refs: refQueries.length ? refQueries : ["default"],
  additions,
  deletions,
  commits: commits.length,
  prs: commits.length,
  label: "Commits",
  source: "github rest commit stats by author",
  updatedAt: new Date().toISOString()
};

await fs.writeFile(output, `${JSON.stringify(stats, null, 2)}\n`, "utf8");
console.log(`Updated ${path.relative(process.cwd(), output)}`);
console.log(`additions=${additions} deletions=${deletions} commits=${commits.length}`);
