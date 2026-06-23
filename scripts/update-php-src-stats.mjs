import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const owner = "php";
const repo = "php-src";
const author = "LamentXU123";
const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, "php-src-stats.json");

if (!token) {
  throw new Error("GITHUB_TOKEN or GH_TOKEN is required.");
}

async function graphql(query, variables) {
  const response = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "lamentxu-php-src-stats"
    },
    body: JSON.stringify({ query, variables })
  });
  const body = await response.json();

  if (!response.ok || body.errors) {
    throw new Error(`GitHub GraphQL failed: ${JSON.stringify(body.errors || body)}`);
  }

  return body.data;
}

const query = `
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
let prs = 0;
let latestMergedAt = null;
const searchQuery = `repo:${owner}/${repo} author:${author} is:pr is:merged`;

do {
  const data = await graphql(query, { query: searchQuery, cursor });
  const page = data.search;

  for (const pull of page.nodes) {
    additions += pull.additions || 0;
    deletions += pull.deletions || 0;
    prs++;

    if (pull.mergedAt && (!latestMergedAt || pull.mergedAt > latestMergedAt)) {
      latestMergedAt = pull.mergedAt;
    }
  }

  cursor = page.pageInfo.hasNextPage ? page.pageInfo.endCursor : null;
} while (cursor);

const stats = {
  owner,
  repo,
  author,
  additions,
  deletions,
  prs,
  label: "已合并 PR",
  source: "github graphql merged pull request additions/deletions",
  latestMergedAt,
  updatedAt: new Date().toISOString()
};

await fs.writeFile(output, `${JSON.stringify(stats, null, 2)}\n`, "utf8");
console.log(`Updated ${path.relative(process.cwd(), output)}`);
console.log(`additions=${additions} deletions=${deletions} merged_prs=${prs}`);
