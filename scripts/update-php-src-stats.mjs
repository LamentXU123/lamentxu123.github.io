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

if (!token) {
  throw new Error("GITHUB_TOKEN or GH_TOKEN is required.");
}

const headers = {
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "User-Agent": "lamentxu-php-src-stats"
};

async function graphql(query, variables) {
  const response = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: {
      ...headers,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query, variables })
  });
  const body = await response.json();

  if (!response.ok || body.errors) {
    throw new Error(`GitHub GraphQL failed: ${JSON.stringify(body.errors || body)}`);
  }

  return body.data;
}

async function restJson(url) {
  const response = await fetch(url, { headers });
  const body = await response.json();

  if (!response.ok) {
    throw new Error(`GitHub REST failed: ${JSON.stringify(body)}`);
  }

  return body;
}

const pullRequestQuery = `
  query($query: String!, $cursor: String) {
    search(type: ISSUE, first: 100, after: $cursor, query: $query) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        ... on PullRequest {
          number
          additions
          deletions
          mergedAt
        }
      }
    }
  }
`;

let cursor = null;
let additions = 0;
let deletions = 0;
let mergedPrs = 0;
let latestMergedAt = null;
const pullSearchQuery = `repo:${owner}/${repo} author:${author} is:pr is:merged`;

do {
  const data = await graphql(pullRequestQuery, { query: pullSearchQuery, cursor });
  const page = data.search;

  for (const pull of page.nodes) {
    additions += pull.additions || 0;
    deletions += pull.deletions || 0;
    mergedPrs++;

    if (pull.mergedAt && (!latestMergedAt || pull.mergedAt > latestMergedAt)) {
      latestMergedAt = pull.mergedAt;
    }
  }

  cursor = page.pageInfo.hasNextPage ? page.pageInfo.endCursor : null;
} while (cursor);

const commitShas = new Set();
for (const commitAuthor of commitAuthors) {
  let page = 1;

  while (true) {
    const query = encodeURIComponent(`repo:${owner}/${repo} author:${commitAuthor}`);
    const result = await restJson(`https://api.github.com/search/commits?q=${query}&per_page=100&page=${page}`);

    for (const item of result.items || []) {
      if (item.sha) {
        commitShas.add(item.sha);
      }
    }

    if (!result.items || result.items.length < 100) {
      break;
    }

    page++;
  }
}

const stats = {
  owner,
  repo,
  author,
  additions,
  deletions,
  prs: commitShas.size,
  label: "\u63d0\u4ea4",
  source: "github graphql merged pull request additions/deletions + github commit search count",
  mergedPrs,
  latestMergedAt,
  updatedAt: new Date().toISOString()
};

await fs.writeFile(output, `${JSON.stringify(stats, null, 2)}\n`, "utf8");
console.log(`Updated ${path.relative(process.cwd(), output)}`);
console.log(`additions=${additions} deletions=${deletions} commits=${commitShas.size} merged_prs=${mergedPrs}`);
