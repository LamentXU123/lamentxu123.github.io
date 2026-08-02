import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const postsDir = path.join(root, "posts");
const maxSummaryLength = Number.parseInt(process.env.FEED_SUMMARY_LENGTH || "500", 10);

const authorName = process.env.FEED_AUTHOR_NAME || "LamentXU";
const authorEmail = process.env.FEED_AUTHOR_EMAIL || "weilindu@php.net";
const siteTitle = process.env.FEED_TITLE || "LamentXU";
const language = process.env.FEED_LANGUAGE || "zh-CN";

function normalizeWhitespace(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function trimTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function stripIndexHtml(value) {
  return value.replace(/\/index\.html$/i, "/");
}

function escapeXml(value) {
  return String(value || "").replace(/[<>&'"]/g, (char) => ({
    "<": "&lt;",
    ">": "&gt;",
    "&": "&amp;",
    "'": "&apos;",
    "\"": "&quot;"
  })[char]);
}

function decodeHtml(value) {
  const entities = {
    amp: "&",
    apos: "'",
    gt: ">",
    lt: "<",
    nbsp: " ",
    quot: "\""
  };

  return String(value || "").replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (match, entity) => {
    if (entity.startsWith("#x") || entity.startsWith("#X")) {
      const codePoint = Number.parseInt(entity.slice(2), 16);
      return Number.isNaN(codePoint) ? match : String.fromCodePoint(codePoint);
    }

    if (entity.startsWith("#")) {
      const codePoint = Number.parseInt(entity.slice(1), 10);
      return Number.isNaN(codePoint) ? match : String.fromCodePoint(codePoint);
    }

    return entities[entity] || match;
  });
}

function parseAttributes(tag) {
  const attributes = {};
  const pattern = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let match;

  while ((match = pattern.exec(tag)) !== null) {
    attributes[match[1].toLowerCase()] = decodeHtml(match[3] ?? match[4] ?? "");
  }

  return attributes;
}

function getMetaContent(html, attributeName, attributeValue) {
  const pattern = /<meta\b[^>]*>/gi;
  let match;

  while ((match = pattern.exec(html)) !== null) {
    const attributes = parseAttributes(match[0]);

    if (attributes[attributeName] === attributeValue && attributes.content) {
      return attributes.content;
    }
  }

  return "";
}

function getHtmlTitle(html) {
  const match = html.match(/<title>([\s\S]*?)<\/title>/i);
  return match ? decodeHtml(match[1]) : "";
}

function stripHtml(value) {
  return decodeHtml(String(value || "")
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " "));
}

function truncateSummary(value) {
  const summary = normalizeWhitespace(value);

  if (!Number.isFinite(maxSummaryLength) || maxSummaryLength <= 0) {
    return summary;
  }

  if (summary.length <= maxSummaryLength) {
    return summary;
  }

  return `${summary.slice(0, maxSummaryLength - 3).trimEnd()}...`;
}

function extractArticleSummary(html) {
  const articleBody = html.match(/<div\b[^>]*class="[^"]*\be-content\b[^"]*"[^>]*>([\s\S]*?)<\/div>/i);
  return articleBody ? stripHtml(articleBody[1]) : "";
}

function toDate(value) {
  if (!value) {
    return null;
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function dateFromSlug(slug) {
  const match = slug.match(/^(\d{4})-(\d{2})-(\d{2})-/);
  return match ? toDate(`${match[1]}-${match[2]}-${match[3]}T00:00:00.000Z`) : null;
}

function extractCategories(html) {
  const categories = new Set();
  const pattern = /<a\b[^>]*>[\s\S]*?<\/a>/gi;
  let match;

  while ((match = pattern.exec(html)) !== null) {
    const tag = match[0];
    const attributes = parseAttributes(tag);

    if (!attributes.class || !attributes.class.split(/\s+/).includes("category-link")) {
      continue;
    }

    const text = normalizeWhitespace(stripHtml(tag));

    if (text) {
      categories.add(text);
    }
  }

  return Array.from(categories);
}

async function getBaseUrl() {
  const configured = process.env.SITE_URL || process.env.URL;

  if (configured) {
    return trimTrailingSlash(configured.trim());
  }

  const cname = await fs.readFile(path.join(root, "CNAME"), "utf8").catch(() => "");
  const domain = cname.trim();

  if (!domain) {
    return "https://example.com";
  }

  return trimTrailingSlash(domain.startsWith("http://") || domain.startsWith("https://")
    ? domain
    : `https://${domain}`);
}

async function getSiteDescription() {
  const indexHtml = await fs.readFile(path.join(root, "index.html"), "utf8").catch(() => "");
  return normalizeWhitespace(getMetaContent(indexHtml, "name", "description")
    || getMetaContent(indexHtml, "property", "og:description")
    || siteTitle);
}

async function getPostFiles() {
  const entries = await fs.readdir(postsDir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }

    const file = path.join(postsDir, entry.name, "index.html");

    try {
      const stat = await fs.stat(file);
      files.push({ file, slug: entry.name, stat });
    } catch {
      // Ignore directories that are not generated posts.
    }
  }

  return files;
}

async function parsePost({ file, slug, stat }, baseUrl) {
  const html = await fs.readFile(file, "utf8");
  const articleSummary = extractArticleSummary(html);

  if (!normalizeWhitespace(articleSummary)) {
    return null;
  }

  const relativeUrl = stripIndexHtml(`/${path.relative(root, file).replace(/\\/g, "/")}`);
  const url = `${baseUrl}${relativeUrl}`;
  const published = toDate(getMetaContent(html, "property", "article:published_time"))
    || dateFromSlug(slug)
    || stat.mtime;
  const updated = toDate(getMetaContent(html, "property", "article:modified_time")) || published;

  return {
    title: normalizeWhitespace(getMetaContent(html, "property", "og:title") || getHtmlTitle(html) || slug),
    url,
    id: url,
    published,
    updated,
    summary: truncateSummary(getMetaContent(html, "name", "description")
      || getMetaContent(html, "property", "og:description")
      || articleSummary),
    categories: extractCategories(html)
  };
}

function renderRss(posts, baseUrl, siteDescription, siteUpdated) {
  const items = posts.map((post) => [
    "    <item>",
    `      <title>${escapeXml(post.title)}</title>`,
    `      <link>${escapeXml(post.url)}</link>`,
    `      <guid isPermaLink="true">${escapeXml(post.id)}</guid>`,
    `      <pubDate>${post.published.toUTCString()}</pubDate>`,
    `      <description>${escapeXml(post.summary)}</description>`,
    `      <author>${escapeXml(`${authorEmail} (${authorName})`)}</author>`,
    ...post.categories.map((category) => `      <category>${escapeXml(category)}</category>`),
    "    </item>"
  ].join("\n")).join("\n");

  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
    "  <channel>",
    `    <title>${escapeXml(siteTitle)}</title>`,
    `    <link>${escapeXml(`${baseUrl}/`)}</link>`,
    `    <description>${escapeXml(siteDescription)}</description>`,
    `    <language>${escapeXml(language)}</language>`,
    `    <lastBuildDate>${siteUpdated.toUTCString()}</lastBuildDate>`,
    `    <atom:link href="${escapeXml(`${baseUrl}/rss.xml`)}" rel="self" type="application/rss+xml" />`,
    items,
    "  </channel>",
    "</rss>",
    ""
  ].join("\n");
}

function renderAtom(posts, baseUrl, siteDescription, siteUpdated) {
  const entries = posts.map((post) => [
    "  <entry>",
    `    <title>${escapeXml(post.title)}</title>`,
    `    <link href="${escapeXml(post.url)}" />`,
    `    <id>${escapeXml(post.id)}</id>`,
    `    <published>${post.published.toISOString()}</published>`,
    `    <updated>${post.updated.toISOString()}</updated>`,
    `    <summary type="text">${escapeXml(post.summary)}</summary>`,
    ...post.categories.map((category) => `    <category term="${escapeXml(category)}" />`),
    "  </entry>"
  ].join("\n")).join("\n");

  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<feed xmlns="http://www.w3.org/2005/Atom">',
    `  <title>${escapeXml(siteTitle)}</title>`,
    `  <subtitle>${escapeXml(siteDescription)}</subtitle>`,
    `  <link href="${escapeXml(`${baseUrl}/`)}" />`,
    `  <link href="${escapeXml(`${baseUrl}/atom.xml`)}" rel="self" type="application/atom+xml" />`,
    `  <id>${escapeXml(`${baseUrl}/`)}</id>`,
    `  <updated>${siteUpdated.toISOString()}</updated>`,
    "  <author>",
    `    <name>${escapeXml(authorName)}</name>`,
    `    <email>${escapeXml(authorEmail)}</email>`,
    "  </author>",
    entries,
    "</feed>",
    ""
  ].join("\n");
}

const baseUrl = await getBaseUrl();
const siteDescription = await getSiteDescription();
const postFiles = await getPostFiles();
const parsedPosts = await Promise.all(postFiles.map((postFile) => parsePost(postFile, baseUrl)));
const posts = parsedPosts
  .filter(Boolean)
  .sort((a, b) => b.published.getTime() - a.published.getTime());
const skippedPosts = parsedPosts.length - posts.length;
const siteUpdated = posts.reduce((latest, post) => {
  const postLatest = post.updated > post.published ? post.updated : post.published;
  return postLatest > latest ? postLatest : latest;
}, posts[0] ? (posts[0].updated > posts[0].published ? posts[0].updated : posts[0].published) : new Date());

await fs.writeFile(path.join(root, "rss.xml"), renderRss(posts, baseUrl, siteDescription, siteUpdated), "utf8");
await fs.writeFile(path.join(root, "atom.xml"), renderAtom(posts, baseUrl, siteDescription, siteUpdated), "utf8");

console.log(`Generated rss.xml and atom.xml for ${posts.length} posts${skippedPosts ? `, skipped ${skippedPosts} empty post${skippedPosts === 1 ? "" : "s"}` : ""}`);
