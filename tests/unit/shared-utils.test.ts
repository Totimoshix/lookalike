import { describe, expect, it } from "vitest";
import { generateLookalikeCandidates, normalizeInputUrl } from "@capstone/shared";

describe("normalizeInputUrl", () => {
  it("adds a scheme and derives the registrable domain", () => {
    const result = normalizeInputUrl("subdomain.example.co.uk/login");

    expect(result.normalizedUrl).toBe("https://subdomain.example.co.uk/login");
    expect(result.registrableDomain).toBe("example.co.uk");
    expect(result.subdomain).toBe("subdomain");
  });
});

describe("generateLookalikeCandidates", () => {
  it("creates candidate variants with multiple patterns", () => {
    const candidates = generateLookalikeCandidates("amazon.com", 40);
    const domains = candidates.map((candidate) => candidate.candidate_domain);

    expect(domains).toContain("amzaon.com");
    expect(domains.some((domain) => domain.includes("secure"))).toBe(true);
    expect(candidates.length).toBeLessThanOrEqual(40);
  });
});

