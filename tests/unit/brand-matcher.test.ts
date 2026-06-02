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
});
