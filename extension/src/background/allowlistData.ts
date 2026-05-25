// Starter allowlist of high-traffic registrable domains. Skipping these avoids
// hammering the API on every navigation to popular sites. In production this
// should be regenerated quarterly from a Tranco top-10k snapshot. Domains here
// are intentionally minimal so the warning flow can be exercised end-to-end
// without a full feed.

export const ALLOWLIST_DOMAINS: readonly string[] = [
  // Search & portals
  "google.com",
  "bing.com",
  "duckduckgo.com",
  "yahoo.com",
  "baidu.com",
  // Social
  "facebook.com",
  "instagram.com",
  "twitter.com",
  "x.com",
  "linkedin.com",
  "reddit.com",
  "tiktok.com",
  "pinterest.com",
  "snapchat.com",
  // Video / media
  "youtube.com",
  "netflix.com",
  "twitch.tv",
  "spotify.com",
  "vimeo.com",
  "disneyplus.com",
  // Shopping
  "amazon.com",
  "ebay.com",
  "etsy.com",
  "shopify.com",
  "walmart.com",
  "target.com",
  "costco.com",
  "bestbuy.com",
  // Productivity & dev
  "microsoft.com",
  "office.com",
  "live.com",
  "outlook.com",
  "github.com",
  "gitlab.com",
  "stackoverflow.com",
  "notion.so",
  "atlassian.com",
  "slack.com",
  "zoom.us",
  "dropbox.com",
  "salesforce.com",
  "adobe.com",
  // News & reference
  "wikipedia.org",
  "cnn.com",
  "bbc.com",
  "bbc.co.uk",
  "nytimes.com",
  "theguardian.com",
  "reuters.com",
  "bloomberg.com",
  // Cloud & infra
  "cloudflare.com",
  "aws.amazon.com",
  "amazonaws.com",
  "azure.com",
  "googleapis.com",
  "gstatic.com",
  // Banks (Canada/US, sample)
  "rbcroyalbank.com",
  "td.com",
  "scotiabank.com",
  "bmo.com",
  "cibc.com",
  "chase.com",
  "bankofamerica.com",
  "wellsfargo.com",
  // Universities (sample)
  "harvard.edu",
  "mit.edu",
  "utoronto.ca",
  // Government (sample)
  "canada.ca",
  "irs.gov",
  "usa.gov",
  // CDN / browser
  "mozilla.org",
  "apple.com",
  "icloud.com"
];
