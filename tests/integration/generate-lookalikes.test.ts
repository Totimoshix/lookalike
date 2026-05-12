import { afterEach, describe, expect, it, vi } from "vitest";
import { generateLookalikeSet } from "../../api/src/services/orchestrator";

describe("generateLookalikeSet", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("returns a versioned candidate set with the requested limit", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            domain: "google.com",
            fuzzy_domains: [
              { domain: "google.com", fuzzer: "Original" },
              { domain: "g00gle.com", fuzzer: "Homoglyph" },
              { domain: "goog1e.com", fuzzer: "Homoglyph" },
              { domain: "gooogle.com", fuzzer: "Repetition" }
            ]
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json"
            }
          }
        )
      )
    );

    const result = await generateLookalikeSet({
      canonical_domain: "google.com",
      brand_name: "Google",
      limit: 2
    });

    expect(result.schema_version).toBe("lookalike-candidates.v2");
    expect(result.canonical_domain).toBe("google.com");
    expect(result.brand_name).toBe("Google");
    expect(result.source).toBe("dnstwister");
    expect(result.candidates).toHaveLength(2);
    expect(result.candidates.map((candidate) => candidate.candidate_domain)).toEqual([
      "g00gle.com",
      "goog1e.com"
    ]);
    expect(result.candidates[0]?.pattern).toBe("homoglyph");
    expect(result.candidates[0]?.notes).toContain("Source: DNSTwister");
    expect(fetch).toHaveBeenCalledWith(
      "https://dnstwister.report/api/fuzz/676f6f676c652e636f6d",
      expect.objectContaining({
        headers: expect.objectContaining({
          accept: "application/json"
        })
      })
    );
  });

  it("surfaces an upstream error when DNSTwister fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response("upstream unavailable", {
          status: 503
        })
      )
    );

    await expect(
      generateLookalikeSet({
        canonical_domain: "google.com",
        limit: 5
      })
    ).rejects.toThrow("DNSTwister lookup failed with status 503");
  });
});
