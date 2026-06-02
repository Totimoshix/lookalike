import { describe, expect, it } from "vitest";
import {
  detectHomoglyphPattern,
  generateLookalikeCandidates,
  isHomoglyphDomain,
  normalizeInputUrl,
  STUFFING_WORDS,
  stripStuffingTokens,
  tokenizeDomainLabel
} from "@capstone/shared";

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

describe("homoglyph detection (Unicode confusables)", () => {
  it("detects Cyrillic 'а' (U+0430) substituted for ASCII 'a'", () => {
    const cyrillicA = "а"; // Cyrillic small letter a
    expect(isHomoglyphDomain(`${cyrillicA}mazon`, "amazon")).toBe(true);
    expect(detectHomoglyphPattern(`${cyrillicA}mazon`, "amazon")).toBe(`${cyrillicA}->a`);
  });

  it("detects Greek alpha (U+03B1) substituted for ASCII 'a'", () => {
    expect(isHomoglyphDomain("αmazon", "amazon")).toBe(true);
  });

  it("still detects ASCII visual swaps (0 -> o)", () => {
    expect(isHomoglyphDomain("amaz0n", "amazon")).toBe(true);
  });

  it("does not flag identical ASCII strings as homoglyphs", () => {
    expect(isHomoglyphDomain("amazon", "amazon")).toBe(false);
  });
});

describe("tokenizeDomainLabel + stripStuffingTokens", () => {
  it("splits a hyphen-separated label", () => {
    expect(tokenizeDomainLabel("payment-sheridancollege")).toEqual(["payment", "sheridancollege"]);
  });

  it("splits underscores and lowercases", () => {
    expect(tokenizeDomainLabel("Secure_Login_Amazon")).toEqual(["secure", "login", "amazon"]);
  });

  it("splits at digit/letter transitions", () => {
    expect(tokenizeDomainLabel("login2bank")).toEqual(["login", "2", "bank"]);
    expect(tokenizeDomainLabel("amaz0n")).toEqual(["amaz", "0", "n"]);
  });

  it("identifies stuffing tokens vs. brand-candidate tokens", () => {
    const { brandCandidates, stuffingTokens } = stripStuffingTokens([
      "payment",
      "sheridancollege"
    ]);
    expect(stuffingTokens).toEqual(["payment"]);
    expect(brandCandidates).toEqual(["sheridancollege"]);
  });

  it("treats numeric-only tokens as stuffing", () => {
    const { brandCandidates, stuffingTokens } = stripStuffingTokens(["login", "2", "bank"]);
    expect(stuffingTokens).toEqual(["login", "2"]);
    expect(brandCandidates).toEqual(["bank"]);
  });

  it("returns no brand candidates when every token is stuffing", () => {
    const { brandCandidates, stuffingTokens } = stripStuffingTokens([
      "secure",
      "login",
      "help"
    ]);
    expect(brandCandidates).toEqual([]);
    expect(stuffingTokens).toEqual(["secure", "login", "help"]);
  });

  it("exports a non-trivial STUFFING_WORDS set", () => {
    expect(STUFFING_WORDS.has("payment")).toBe(true);
    expect(STUFFING_WORDS.has("login")).toBe(true);
    expect(STUFFING_WORDS.has("secure")).toBe(true);
    expect(STUFFING_WORDS.has("app")).toBe(false); // intentionally excluded
  });
});

