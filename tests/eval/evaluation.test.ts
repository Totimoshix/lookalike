import { describe, expect, it } from "vitest";
import { runEvaluation } from "../../api/src/eval/evaluate";

// Regression gate on the offline lookalike-detection core. Thresholds sit with
// deliberate margin below the observed numbers (precision 1.0, recall 0.94,
// FP-rate 0.0) so ordinary scoring tweaks don't flake CI — but a NEW false
// positive on a legit domain, or a recall collapse, fails the build.
describe("detection accuracy (offline evaluation harness)", () => {
  it("meets precision / recall / false-positive thresholds on the labeled corpus", async () => {
    const m = await runEvaluation();

    expect(m.total).toBeGreaterThanOrEqual(50);
    expect(m.precision).toBeGreaterThanOrEqual(0.95);
    expect(m.recall).toBeGreaterThanOrEqual(0.85);
    expect(m.accuracy).toBeGreaterThanOrEqual(0.9);
    expect(m.falsePositiveRate).toBeLessThanOrEqual(0.05);
  });

  it("never flags a legitimate domain (the 'legit domains are top priority' invariant)", async () => {
    const m = await runEvaluation();
    // Every legit bucket — catalog canonicals, Tranco-popular, and the obscure
    // non-allowlisted FP-stress set — must be 100% clean (zero false positives).
    for (const group of ["legit-catalog", "legit-popular", "legit-obscure"]) {
      const g = m.byGroup[group];
      expect(g, group).toBeDefined();
      expect(g.correct, `${group} had a false positive`).toBe(g.total);
    }
    expect(m.falsePositive).toBe(0);
  });
});
