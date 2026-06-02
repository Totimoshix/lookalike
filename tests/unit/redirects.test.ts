import { describe, expect, it } from "vitest";
import { areDifferentRegistrableDomains, isBlockedFetchTarget } from "@capstone/shared";

describe("areDifferentRegistrableDomains", () => {
  it("detects an off-domain redirect", () => {
    expect(areDifferentRegistrableDomains("https://sherdiancollege.ca", "https://cf.miniroad.store/x")).toBe(true);
  });
  it("treats apex vs www as the same registrable domain", () => {
    expect(areDifferentRegistrableDomains("https://example.com", "https://www.example.com")).toBe(false);
  });
  it("treats subdomains of the same registrable domain as same", () => {
    expect(areDifferentRegistrableDomains("https://google.com", "https://sites.google.com/x")).toBe(false);
  });
  it("returns false on unparseable input", () => {
    expect(areDifferentRegistrableDomains("not a url", "https://x.com")).toBe(false);
  });
});

describe("isBlockedFetchTarget (SSRF guard)", () => {
  it("blocks loopback / private / link-local / metadata", () => {
    for (const u of [
      "http://127.0.0.1/",
      "http://localhost:8080",
      "http://10.0.0.5/",
      "http://192.168.1.1/",
      "http://172.16.0.1/",
      "http://169.254.169.254/latest/meta-data",
      "http://[::1]/",
      "http://0.0.0.0/"
    ]) {
      expect(isBlockedFetchTarget(u), u).toBe(true);
    }
  });
  it("blocks non-http(s) schemes", () => {
    expect(isBlockedFetchTarget("ftp://example.com")).toBe(true);
    expect(isBlockedFetchTarget("file:///etc/passwd")).toBe(true);
  });
  it("allows ordinary public URLs", () => {
    expect(isBlockedFetchTarget("https://cf.miniroad.store/api/v1/px2")).toBe(false);
    expect(isBlockedFetchTarget("https://example.com")).toBe(false);
    // public IP literal
    expect(isBlockedFetchTarget("http://8.8.8.8/")).toBe(false);
  });
});
