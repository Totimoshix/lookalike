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

  it("returns unknown for unrelated domains instead of forcing the nearest catalog brand", async () => {
    const result = await inferBrandMatch({
      analyzedUrl: "https://theverge.com",
      normalizedDomain: "theverge.com",
      pageTitle: null,
      bodyText: "",
      brandOverride: undefined
    });

    expect(result.method).toBe("unknown");
    expect(result.brand_name).toBe("Unknown");
    expect(result.canonical_domain).toBe("theverge.com");
  });
});
