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
    brandName: "Amazon",
    canonicalDomain: "amazon.com",
    aliases: ["amazon prime", "aws"],
    keywords: ["amazon", "prime", "orders", "signin", "delivery"],
    industry: "retail",
    securityContact: "stop-spoofing@amazon.com"
  },
  {
    brandName: "Google",
    canonicalDomain: "google.com",
    aliases: ["gmail", "google workspace"],
    keywords: ["google", "gmail", "workspace", "account", "verify"],
    industry: "technology",
    securityContact: "security@google.com"
  },
  {
    brandName: "Microsoft",
    canonicalDomain: "microsoft.com",
    aliases: ["office 365", "outlook", "azure"],
    keywords: ["microsoft", "outlook", "office", "azure", "signin"],
    industry: "technology",
    securityContact: "secure@microsoft.com"
  },
  {
    brandName: "Apple",
    canonicalDomain: "apple.com",
    aliases: ["icloud", "itunes"],
    keywords: ["apple", "icloud", "id", "verify", "account"],
    industry: "technology",
    securityContact: "product-security@apple.com"
  },
  {
    brandName: "PayPal",
    canonicalDomain: "paypal.com",
    aliases: ["paypal business"],
    keywords: ["paypal", "wallet", "payment", "billing", "secure"],
    industry: "payments",
    securityContact: "phishing@paypal.com"
  },
  {
    brandName: "Netflix",
    canonicalDomain: "netflix.com",
    aliases: ["netflix billing"],
    keywords: ["netflix", "streaming", "billing", "signin", "secure"],
    industry: "media",
    securityContact: "phishing@netflix.com"
  },
  {
    brandName: "Bank of America",
    canonicalDomain: "bankofamerica.com",
    aliases: ["boa", "bofa"],
    keywords: ["bank", "america", "secure", "login", "account"],
    industry: "banking",
    securityContact: null
  },
  {
    brandName: "Sheridan College",
    canonicalDomain: "sheridancollege.ca",
    aliases: ["sheridan"],
    keywords: ["sheridan", "college", "student", "portal", "login"],
    industry: "education",
    securityContact: "security@sheridancollege.ca"
  }
];

