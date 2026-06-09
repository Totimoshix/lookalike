import { describe, expect, it } from "vitest";
import { inferBrandMatch } from "../../api/src/services/brandMatcher";

describe("inferBrandMatch", () => {
  it("matches exact-label lookalike TLD swaps to the canonical brand", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://amazon.xyz",
      normalizedDomain: "amazon.xyz",
      pageTitle: null,
      bodyText: "",
      brandOverride: undefined
    });

    expect(result.brand_name).toBe("Amazon");
    expect(result.canonical_domain).toBe("amazon.com");
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it("matches strong confusable-character lookalikes to the intended brand", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://1mazon.ca",
      normalizedDomain: "1mazon.ca",
      pageTitle: null,
      bodyText: "",
      brandOverride: undefined
    });

    expect(result.brand_name).toBe("Amazon");
    expect(result.canonical_domain).toBe("amazon.com");
    expect(result.method).toBe("heuristic");
    expect(result.confidence).toBeGreaterThanOrEqual(0.8);
  });

  it("matches expanded-catalog brands (Chase) when the catalog grew beyond the initial set", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://chase-login-secure.com",
      normalizedDomain: "chase-login-secure.com",
      pageTitle: null,
      bodyText: "",
      brandOverride: undefined,
      skipLlm: true
    });

    expect(result.brand_name).toBe("Chase");
    expect(result.canonical_domain).toBe("chase.com");
    expect(result.confidence).toBeGreaterThanOrEqual(0.6);
  });

  it("returns unknown for unrelated domains instead of forcing the nearest catalog brand", async () => {
    // Domain must be unlikely to appear in Tranco top-10k AND lexically far
    // from any catalog brand. Random made-up registrable label.
    const result = await inferBrandMatch({
      analyzedUrl: "https://myverysmallpersonalblogprojectxyz.com",
      normalizedDomain: "myverysmallpersonalblogprojectxyz.com",
      pageTitle: null,
      bodyText: "",
      brandOverride: undefined,
      skipLlm: true
    });

    expect(result.method).toBe("unknown");
    expect(result.brand_name).toBe("Unknown");
    expect(result.canonical_domain).toBe("myverysmallpersonalblogprojectxyz.com");
  });
});

describe("inferBrandMatch — universal resolver (keyword stuffing + Tranco)", () => {
  it("identifies a catalog brand wrapped in stuffing words (payment-sheridancollege.ca)", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://payment-sheridancollege.ca",
      normalizedDomain: "payment-sheridancollege.ca",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.brand_name).toBe("Sheridan College");
    expect(result.canonical_domain).toBe("sheridancollege.ca");
    expect(result.method).toBe("catalog");
    expect(result.confidence).toBeGreaterThanOrEqual(0.85);
    expect(result.matched_keywords).toContain("payment");
  });

  it("identifies a catalog brand with stuffing prefix (secure-google.com)", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://secure-google.com",
      normalizedDomain: "secure-google.com",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.brand_name).toBe("Google");
    expect(result.confidence).toBeGreaterThanOrEqual(0.85);
  });

  it("identifies an uncatalogued brand via Tranco top-10k (support-wikipedia.org)", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://support-wikipedia.org",
      normalizedDomain: "support-wikipedia.org",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.brand_name).toBe("Wikipedia");
    expect(result.canonical_domain).toBe("wikipedia.org");
    expect(result.method).toBe("heuristic");
    expect(result.confidence).toBeGreaterThanOrEqual(0.75);
  });

  it("returns unknown when only stuffing tokens are present (secure-login-help.com)", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://secure-login-help.com",
      normalizedDomain: "secure-login-help.com",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.method).toBe("unknown");
  });

  it("returns unknown for completely uncatalogued, non-Tranco domains", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://xyz-completely-fake-thing.io",
      normalizedDomain: "xyz-completely-fake-thing.io",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.method).toBe("unknown");
  });

  it("fuzzy-matches a near-miss typosquat to the catalogued brand", async () => {
    // single transposition: sherdiancollege ↔ sheridancollege
    const result = await inferBrandMatch({
      analyzedUrl: "https://sherdiancollege.ca",
      normalizedDomain: "sherdiancollege.ca",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.brand_name).toBe("Sheridan College");
    expect(result.canonical_domain).toBe("sheridancollege.ca");
    expect(result.method).toBe("heuristic");
    expect(result.confidence).toBeGreaterThanOrEqual(0.85);
  });

  it("fuzzy-matches an obvious brand typo (amazo → amazon)", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://amazo.com",
      normalizedDomain: "amazo.com",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.brand_name).toBe("Amazon");
    expect(result.confidence).toBeGreaterThanOrEqual(0.85);
  });

  it("does not fuzzy-match an unrelated domain", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://mybusinesssite.ca",
      normalizedDomain: "mybusinesssite.ca",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.method).toBe("unknown");
  });

  it("resolves an uncatalogued brand lookalike via fuzzy Tranco (faceboook → facebook)", async () => {
    // Facebook is NOT in the 50-entry catalog, so before the fuzzy-Tranco pass
    // faceboook.com resolved to Unknown and scored Safe. It now matches.
    const result = await inferBrandMatch({
      analyzedUrl: "https://faceboook.com",
      normalizedDomain: "faceboook.com",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.brand_name).toBe("Facebook");
    expect(result.canonical_domain).toBe("facebook.com");
    expect(result.method).toBe("heuristic");
    expect(result.confidence).toBeGreaterThanOrEqual(0.8);
  });

  it("resolves another uncatalogued fuzzy-Tranco lookalike (instagran → instagram)", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://instagran.com",
      normalizedDomain: "instagran.com",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.brand_name).toBe("Instagram");
    expect(result.canonical_domain).toBe("instagram.com");
    expect(result.method).toBe("heuristic");
  });

  it("does NOT fuzzy-match front-loaded near-misses of common Tranco words (FP guard)", async () => {
    // Each of these is Damerau-Levenshtein 1 from a popular Tranco label but the
    // difference is at the FRONT, so Jaro-Winkler stays under the 0.92 gate.
    for (const d of ["mature.com", "median.io", "literature.org", "signature.app"]) {
      const result = await inferBrandMatch({
        analyzedUrl: `https://${d}`,
        normalizedDomain: d,
        pageTitle: null,
        bodyText: "",
        skipLlm: true
      });
      expect(result.method, d).toBe("unknown");
    }
  });

  it("does not match generic short Tranco tokens as brands (biz/app/web → unknown)", async () => {
    // Regression: "…-biz-…" used to exact-match the Tranco label biz.ua and
    // turn random gibberish into a bogus "Biz" brand hit (→ false High/Critical).
    for (const d of [
      "sp1ct6-slarnor-biz-qravtek-vromnix.pa",
      "random-web-thing-xyz.net",
      "my-app-launcher-9000.io"
    ]) {
      const result = await inferBrandMatch({
        analyzedUrl: `https://${d}`,
        normalizedDomain: d,
        pageTitle: null,
        bodyText: "",
        skipLlm: true
      });
      expect(result.method, d).toBe("unknown");
    }
  });

  it("does not copy catalog SEO keywords into an override match", async () => {
    // Regression: a brand_override that hits a catalog entry used to return
    // the entry's keyword list ("signin", "delivery", …) as matched_keywords,
    // which the scorer then misread as keyword stuffing in the domain.
    const result = await inferBrandMatch({
      analyzedUrl: "https://cmazon.com",
      normalizedDomain: "cmazon.com",
      pageTitle: null,
      bodyText: "",
      brandOverride: "amazon.com",
      skipLlm: true
    });
    expect(result.method).toBe("override");
    expect(result.canonical_domain).toBe("amazon.com");
    expect(result.matched_keywords).toEqual([]);
  });

  it("does not claim a shared host's label as the impersonated brand", async () => {
    // blogspot.com is a shared host; phishing lives on the subdomain. The
    // resolver must NOT report brand_name "Blogspot".
    const result = await inferBrandMatch({
      analyzedUrl: "https://galeripemenangshopee012.blogspot.com",
      normalizedDomain: "blogspot.com",
      pageTitle: null,
      bodyText: "",
      skipLlm: true
    });
    expect(result.brand_name).not.toBe("Blogspot");
    expect(result.method).toBe("unknown");
  });
});
