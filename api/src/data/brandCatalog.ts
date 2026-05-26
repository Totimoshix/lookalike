export type BrandCatalogEntry = {
  brandName: string;
  canonicalDomain: string;
  aliases: string[];
  keywords: string[];
  industry: string;
  securityContact: string | null;
};

export const brandCatalog: BrandCatalogEntry[] = [

  {
    brandName: "Google",
    canonicalDomain: "google.com",
    aliases: ["gmail", "google workspace", "google drive", "google pay"],
    keywords: ["google", "gmail", "workspace", "account", "verify", "drive", "docs"],
    industry: "technology",
    securityContact: "security@google.com"
  },
  {
    brandName: "Microsoft",
    canonicalDomain: "microsoft.com",
    aliases: ["office 365", "outlook", "azure", "teams", "onedrive", "xbox"],
    keywords: ["microsoft", "outlook", "office", "azure", "signin", "teams", "onedrive", "xbox"],
    industry: "technology",
    securityContact: "secure@microsoft.com"
  },
  {
    brandName: "Apple",
    canonicalDomain: "apple.com",
    aliases: ["icloud", "itunes", "apple id", "app store"],
    keywords: ["apple", "icloud", "id", "verify", "account", "itunes", "appstore"],
    industry: "technology",
    securityContact: "product-security@apple.com"
  },
  {
    brandName: "Meta",
    canonicalDomain: "meta.com",
    aliases: ["facebook", "instagram", "whatsapp", "messenger"],
    keywords: ["facebook", "instagram", "whatsapp", "meta", "messenger", "account", "login"],
    industry: "technology",
    securityContact: "phish@fb.com"
  },
  {
    brandName: "LinkedIn",
    canonicalDomain: "linkedin.com",
    aliases: ["linkedin jobs", "linkedin premium"],
    keywords: ["linkedin", "profile", "jobs", "network", "connect", "signin"],
    industry: "technology",
    securityContact: "phishing@linkedin.com"
  },
  {
    brandName: "Dropbox",
    canonicalDomain: "dropbox.com",
    aliases: ["dropbox business"],
    keywords: ["dropbox", "files", "share", "storage", "signin"],
    industry: "technology",
    securityContact: "abuse@dropbox.com"
  },
  {
    brandName: "Adobe",
    canonicalDomain: "adobe.com",
    aliases: ["adobe creative cloud", "acrobat", "adobe sign"],
    keywords: ["adobe", "creative", "cloud", "acrobat", "sign", "pdf", "signin"],
    industry: "technology",
    securityContact: "psirt@adobe.com"
  },
  {
    brandName: "Zoom",
    canonicalDomain: "zoom.us",
    aliases: ["zoom meeting", "zoom webinar"],
    keywords: ["zoom", "meeting", "webinar", "join", "signin", "conference"],
    industry: "technology",
    securityContact: "security@zoom.us"
  },
  {
    brandName: "Docusign",
    canonicalDomain: "docusign.com",
    aliases: ["docusign envelope"],
    keywords: ["docusign", "sign", "document", "envelope", "esign", "review"],
    industry: "technology",
    securityContact: "abuse@docusign.com"
  },
  {
    brandName: "Slack",
    canonicalDomain: "slack.com",
    aliases: ["slack workspace"],
    keywords: ["slack", "workspace", "channel", "signin", "team"],
    industry: "technology",
    securityContact: "security@slack.com"
  },
  {
    brandName: "Amazon",
    canonicalDomain: "amazon.com",
    aliases: ["amazon prime", "aws", "amazon web services"],
    keywords: ["amazon", "prime", "orders", "signin", "delivery", "aws"],
    industry: "retail",
    securityContact: "stop-spoofing@amazon.com"
  },
  {
    brandName: "Cloudflare",
    canonicalDomain: "cloudflare.com",
    aliases: ["cloudflare pages", "cloudflare workers"],
    keywords: ["cloudflare", "dns", "dashboard", "login", "account"],
    industry: "technology",
    securityContact: "abuse@cloudflare.com"
  },

  {
    brandName: "PayPal",
    canonicalDomain: "paypal.com",
    aliases: ["paypal business", "paypal checkout"],
    keywords: ["paypal", "wallet", "payment", "billing", "secure", "transfer"],
    industry: "payments",
    securityContact: "phishing@paypal.com"
  },
  {
    brandName: "Stripe",
    canonicalDomain: "stripe.com",
    aliases: ["stripe payments", "stripe checkout"],
    keywords: ["stripe", "payment", "checkout", "billing", "dashboard"],
    industry: "payments",
    securityContact: "phishing@stripe.com"
  },
  {
    brandName: "Square",
    canonicalDomain: "squareup.com",
    aliases: ["square payments", "cash app"],
    keywords: ["square", "squareup", "cashapp", "payment", "pos", "billing"],
    industry: "payments",
    securityContact: "phishing@squareup.com"
  },
  {
    brandName: "Interac",
    canonicalDomain: "interac.ca",
    aliases: ["interac e-transfer", "interac online"],
    keywords: ["interac", "etransfer", "transfer", "deposit", "payment", "canada"],
    industry: "payments",
    securityContact: "phishing@interac.ca"
  },
  {
    brandName: "Bank of America",
    canonicalDomain: "bankofamerica.com",
    aliases: ["boa", "bofa", "merrill lynch"],
    keywords: ["bank", "america", "secure", "login", "account", "checking", "merrill"],
    industry: "banking",
    securityContact: null
  },
  {
    brandName: "Chase",
    canonicalDomain: "chase.com",
    aliases: ["jpmorgan chase", "chase bank"],
    keywords: ["chase", "bank", "login", "account", "credit", "card", "secure"],
    industry: "banking",
    securityContact: "phishing@chase.com"
  },
  {
    brandName: "Wells Fargo",
    canonicalDomain: "wellsfargo.com",
    aliases: ["wells fargo bank"],
    keywords: ["wellsfargo", "bank", "login", "account", "secure", "card"],
    industry: "banking",
    securityContact: null
  },
  {
    brandName: "Citibank",
    canonicalDomain: "citi.com",
    aliases: ["citi", "citigroup"],
    keywords: ["citi", "citibank", "login", "account", "card", "secure"],
    industry: "banking",
    securityContact: "spoof@citicorp.com"
  },
  {
    brandName: "Royal Bank of Canada",
    canonicalDomain: "rbc.com",
    aliases: ["rbc", "rbc royal bank"],
    keywords: ["rbc", "royal", "bank", "login", "account", "canada", "secure"],
    industry: "banking",
    securityContact: "phishing@rbc.com"
  },
  {
    brandName: "TD Bank",
    canonicalDomain: "td.com",
    aliases: ["td canada trust", "td bank group"],
    keywords: ["td", "tdbank", "canada", "trust", "login", "account", "secure"],
    industry: "banking",
    securityContact: "tdphishing@td.com"
  },
  {
    brandName: "Scotiabank",
    canonicalDomain: "scotiabank.com",
    aliases: ["scotia", "bank of nova scotia"],
    keywords: ["scotiabank", "scotia", "login", "account", "secure", "canada"],
    industry: "banking",
    securityContact: null
  },
  {
    brandName: "BMO",
    canonicalDomain: "bmo.com",
    aliases: ["bank of montreal", "bmo financial"],
    keywords: ["bmo", "montreal", "bank", "login", "account", "secure", "canada"],
    industry: "banking",
    securityContact: null
  },
  {
    brandName: "CIBC",
    canonicalDomain: "cibc.com",
    aliases: ["canadian imperial bank"],
    keywords: ["cibc", "bank", "login", "account", "secure", "canada", "imperial"],
    industry: "banking",
    securityContact: null
  },
  {
    brandName: "American Express",
    canonicalDomain: "americanexpress.com",
    aliases: ["amex"],
    keywords: ["amex", "american", "express", "card", "login", "account", "rewards"],
    industry: "banking",
    securityContact: "phishing@americanexpress.com"
  },
  {
    brandName: "Coinbase",
    canonicalDomain: "coinbase.com",
    aliases: ["coinbase pro", "coinbase wallet"],
    keywords: ["coinbase", "crypto", "bitcoin", "wallet", "login", "account", "trade"],
    industry: "cryptocurrency",
    securityContact: "phishing@coinbase.com"
  },
  {
    brandName: "Binance",
    canonicalDomain: "binance.com",
    aliases: ["binance exchange"],
    keywords: ["binance", "crypto", "bitcoin", "trade", "wallet", "login", "account"],
    industry: "cryptocurrency",
    securityContact: "abuse@binance.com"
  },
  {
    brandName: "eBay",
    canonicalDomain: "ebay.com",
    aliases: ["ebay motors"],
    keywords: ["ebay", "auction", "buy", "sell", "signin", "account", "listing"],
    industry: "retail",
    securityContact: "spoof@ebay.com"
  },
  {
    brandName: "Walmart",
    canonicalDomain: "walmart.com",
    aliases: ["walmart+", "walmart grocery"],
    keywords: ["walmart", "shopping", "order", "account", "signin", "delivery"],
    industry: "retail",
    securityContact: null
  },
  {
    brandName: "Shopify",
    canonicalDomain: "shopify.com",
    aliases: ["shopify payments", "shopify store"],
    keywords: ["shopify", "store", "admin", "login", "account", "dashboard"],
    industry: "retail",
    securityContact: "phishing@shopify.com"
  },
  {
    brandName: "DHL",
    canonicalDomain: "dhl.com",
    aliases: ["dhl express", "dhl parcel"],
    keywords: ["dhl", "parcel", "delivery", "tracking", "shipment", "express"],
    industry: "logistics",
    securityContact: "phishing-dpdhl@dhl.com"
  },
  {
    brandName: "FedEx",
    canonicalDomain: "fedex.com",
    aliases: ["fedex express", "fedex ground"],
    keywords: ["fedex", "delivery", "tracking", "shipment", "package", "express"],
    industry: "logistics",
    securityContact: "abuse@fedex.com"
  },
  {
    brandName: "UPS",
    canonicalDomain: "ups.com",
    aliases: ["ups my choice"],
    keywords: ["ups", "delivery", "tracking", "shipment", "package", "mychoice"],
    industry: "logistics",
    securityContact: "fraud@ups.com"
  },
  {
    brandName: "Canada Post",
    canonicalDomain: "canadapost.ca",
    aliases: ["postes canada"],
    keywords: ["canadapost", "canada", "post", "parcel", "delivery", "tracking"],
    industry: "logistics",
    securityContact: null
  },
  {
    brandName: "Netflix",
    canonicalDomain: "netflix.com",
    aliases: ["netflix billing"],
    keywords: ["netflix", "streaming", "billing", "signin", "secure", "account"],
    industry: "media",
    securityContact: "phishing@netflix.com"
  },
  {
    brandName: "Spotify",
    canonicalDomain: "spotify.com",
    aliases: ["spotify premium"],
    keywords: ["spotify", "music", "premium", "billing", "login", "account"],
    industry: "media",
    securityContact: "abuse@spotify.com"
  },
  {
    brandName: "Disney+",
    canonicalDomain: "disneyplus.com",
    aliases: ["disney plus", "disney streaming"],
    keywords: ["disney", "disneyplus", "streaming", "billing", "login", "account"],
    industry: "media",
    securityContact: null
  },
  {
    brandName: "Canada Revenue Agency",
    canonicalDomain: "canada.ca",
    aliases: ["cra", "my account cra", "netfile"],
    keywords: ["cra", "revenue", "canada", "tax", "netfile", "myaccount", "refund", "benefit"],
    industry: "government",
    securityContact: "phishing@cra-arc.gc.ca"
  },
  {
    brandName: "Service Canada",
    canonicalDomain: "canada.ca",
    aliases: ["my service canada", "ei", "cpp"],
    keywords: ["servicecanada", "ei", "employment", "insurance", "cpp", "benefit", "sin"],
    industry: "government",
    securityContact: null
  },
  {
    brandName: "IRS",
    canonicalDomain: "irs.gov",
    aliases: ["internal revenue service"],
    keywords: ["irs", "tax", "refund", "return", "federal", "revenue", "filing"],
    industry: "government",
    securityContact: "phishing@irs.gov"
  },
  {
    brandName: "Rogers",
    canonicalDomain: "rogers.com",
    aliases: ["rogers wireless", "rogers internet", "fido"],
    keywords: ["rogers", "wireless", "internet", "billing", "account", "fido"],
    industry: "telecommunications",
    securityContact: null
  },
  {
    brandName: "Bell",
    canonicalDomain: "bell.ca",
    aliases: ["bell canada", "bell mobility"],
    keywords: ["bell", "canada", "wireless", "internet", "billing", "account"],
    industry: "telecommunications",
    securityContact: null
  },
  {
    brandName: "Telus",
    canonicalDomain: "telus.com",
    aliases: ["telus mobility", "koodo"],
    keywords: ["telus", "wireless", "internet", "billing", "account", "koodo"],
    industry: "telecommunications",
    securityContact: null
  },
  {
    brandName: "AT&T",
    canonicalDomain: "att.com",
    aliases: ["at&t wireless", "att internet"],
    keywords: ["att", "wireless", "internet", "billing", "account", "mobile"],
    industry: "telecommunications",
    securityContact: "abuse@att.net"
  },
  {
    brandName: "Verizon",
    canonicalDomain: "verizon.com",
    aliases: ["verizon wireless"],
    keywords: ["verizon", "wireless", "billing", "account", "mobile", "fios"],
    industry: "telecommunications",
    securityContact: "abuse@verizon.com"
  },
  {
    brandName: "Sheridan College",
    canonicalDomain: "sheridancollege.ca",
    aliases: ["sheridan"],
    keywords: ["sheridan", "college", "student", "portal", "login"],
    industry: "education",
    securityContact: "security@sheridancollege.ca"
  },
  {
    brandName: "University of Toronto",
    canonicalDomain: "utoronto.ca",
    aliases: ["uoft", "u of t"],
    keywords: ["utoronto", "uoft", "student", "portal", "login", "quercus"],
    industry: "education",
    securityContact: "phishing@utoronto.ca"
  },
  {
    brandName: "Manulife",
    canonicalDomain: "manulife.com",
    aliases: ["manulife financial", "john hancock"],
    keywords: ["manulife", "insurance", "benefits", "login", "account", "group"],
    industry: "insurance",
    securityContact: null
  },
  {
    brandName: "Sun Life",
    canonicalDomain: "sunlife.com",
    aliases: ["sun life financial"],
    keywords: ["sunlife", "insurance", "benefits", "login", "account", "claims"],
    industry: "insurance",
    securityContact: null
  },
];
