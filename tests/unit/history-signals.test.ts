import { afterEach, describe, expect, it, vi } from "vitest";
import { collectPassiveHistorySignals } from "../../api/src/services/historySignals";

describe("collectPassiveHistorySignals", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("builds passive history evidence and provider diagnostics from crt.sh and archive data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);

        if (url.includes("crt.sh")) {
          return new Response(
            JSON.stringify([
              {
                issuer_name: "Let's Encrypt",
                common_name: "amazon-login-support.com",
                name_value: "amazon-login-support.com\nwww.amazon-login-support.com",
                not_before: "2026-03-01T00:00:00Z"
              }
            ]),
            {
              status: 200,
              headers: {
                "content-type": "application/json"
              }
            }
          );
        }

        return new Response(
          JSON.stringify([
            ["timestamp", "original", "statuscode", "mimetype"],
            ["20260305010203", "https://amazon-login-support.com/", "200", "text/html"]
          ]),
          {
            status: 200,
            headers: {
              "content-type": "application/json"
            }
          }
        );
      })
    );

    const result = await collectPassiveHistorySignals({
      domain: "amazon-login-support.com",
      ownershipChangesDetected: true
    });

    expect(result.passiveHistory.passive_dns_observed).toBe(true);
    expect(result.passiveHistory.passive_dns_notes[0]).toContain("crt.sh");
    expect(result.passiveHistory.archive_first_seen_days).not.toBeNull();
    expect(result.passiveHistory.ownership_changes_detected).toBe(true);
    expect(result.dnsHistoryChanges).toBeGreaterThanOrEqual(1);
    expect(result.diagnostics.every((diagnostic) => diagnostic.status === "ok")).toBe(true);
  });
});
