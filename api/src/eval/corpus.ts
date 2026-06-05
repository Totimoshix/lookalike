// Labeled evaluation corpus for the lookalike-detection core.
//
// This is a hand-curated, deliberately honest benchmark — it is NOT cherry-
// picked to make the detector look perfect. It mixes easy and hard cases so the
// measured precision/recall reflect real behaviour, including known gaps (e.g.
// stuffing words the catalog doesn't yet know, or brands outside the Tranco
// top-10k). Misses here are findings, not failures.
//
// `label`:
//   "phish" — a lookalike / typosquat / brand-impersonation domain that SHOULD
//             be flagged (verdict High or above).
//   "legit" — a domain that SHOULD NOT be flagged (verdict Safe/Low/Medium).
//
// `group` buckets results so the report can show WHERE the detector is strong
// or weak (homoglyph vs stuffing vs typo; legit-popular vs legit-obscure).

export type EvalLabel = "phish" | "legit";

export type EvalEntry = {
  url: string;
  label: EvalLabel;
  group: string;
  note?: string;
};

export const EVAL_CORPUS: EvalEntry[] = [
  // ───────────────────────── PHISH: homoglyph / digit substitution ──────────
  { url: "https://g00gle.com", label: "phish", group: "homoglyph" },
  { url: "https://paypa1.com", label: "phish", group: "homoglyph" },
  { url: "https://micros0ft.com", label: "phish", group: "homoglyph" },
  { url: "https://1mazon.ca", label: "phish", group: "homoglyph" },
  { url: "https://app1e.com", label: "phish", group: "homoglyph" },
  { url: "https://netf1ix.com", label: "phish", group: "homoglyph" },
  { url: "https://c0inbase.com", label: "phish", group: "homoglyph" },
  { url: "https://0utlook.com", label: "phish", group: "homoglyph" },

  // ───────────────────────── PHISH: character typo / transposition ──────────
  { url: "https://gooogle.com", label: "phish", group: "typo" },
  { url: "https://amazo.com", label: "phish", group: "typo" },
  { url: "https://microsofy.com", label: "phish", group: "typo" },
  { url: "https://sherdiancollege.ca", label: "phish", group: "typo", note: "transposition of sheridancollege" },
  { url: "https://faceboook.com", label: "phish", group: "typo", note: "uncatalogued brand via Tranco fuzzy" },
  { url: "https://facebok.com", label: "phish", group: "typo" },
  { url: "https://instagran.com", label: "phish", group: "typo" },
  { url: "https://whatsap.com", label: "phish", group: "typo" },
  { url: "https://linkedln.com", label: "phish", group: "typo", note: "i->l" },
  { url: "https://twiter.com", label: "phish", group: "typo" },
  { url: "https://youtubee.com", label: "phish", group: "typo" },
  { url: "https://wikipdia.org", label: "phish", group: "typo" },

  // ───────────────────────── PHISH: keyword stuffing around a real brand ────
  { url: "https://payment-sheridancollege.ca", label: "phish", group: "stuffing" },
  { url: "https://secure-google.com", label: "phish", group: "stuffing" },
  { url: "https://chase-login-secure.com", label: "phish", group: "stuffing" },
  { url: "https://micros0ft-login.com", label: "phish", group: "stuffing" },
  { url: "https://amaz0n-account-verify.com", label: "phish", group: "stuffing" },
  { url: "https://appleid-verify.com", label: "phish", group: "stuffing" },
  { url: "https://paypal-account-confirm.com", label: "phish", group: "stuffing" },
  { url: "https://rbc-secure-login.com", label: "phish", group: "stuffing" },
  { url: "https://interac-etransfer-verify.com", label: "phish", group: "stuffing" },
  { url: "https://wellsfargo-alert-login.com", label: "phish", group: "stuffing" },
  { url: "https://coinbase-wallet-verify.com", label: "phish", group: "stuffing" },
  { url: "https://netflix-billing-update.com", label: "phish", group: "stuffing" },
  { url: "https://dropbox-shared-document.com", label: "phish", group: "stuffing" },
  { url: "https://support-wikipedia.org", label: "phish", group: "stuffing", note: "uncatalogued brand via Tranco" },

  // ───────────────────────── LEGIT: brand-catalog canonicals (self) ─────────
  { url: "https://google.com", label: "legit", group: "legit-catalog" },
  { url: "https://amazon.com", label: "legit", group: "legit-catalog" },
  { url: "https://microsoft.com", label: "legit", group: "legit-catalog" },
  { url: "https://apple.com", label: "legit", group: "legit-catalog" },
  { url: "https://paypal.com", label: "legit", group: "legit-catalog" },
  { url: "https://netflix.com", label: "legit", group: "legit-catalog" },
  { url: "https://chase.com", label: "legit", group: "legit-catalog" },
  { url: "https://coinbase.com", label: "legit", group: "legit-catalog" },
  { url: "https://dropbox.com", label: "legit", group: "legit-catalog" },
  { url: "https://sheridancollege.ca", label: "legit", group: "legit-catalog" },

  // ───────────────────────── LEGIT: popular sites (Tranco top-10k) ──────────
  { url: "https://facebook.com", label: "legit", group: "legit-popular" },
  { url: "https://instagram.com", label: "legit", group: "legit-popular" },
  { url: "https://wikipedia.org", label: "legit", group: "legit-popular" },
  { url: "https://github.com", label: "legit", group: "legit-popular" },
  { url: "https://reddit.com", label: "legit", group: "legit-popular" },
  { url: "https://youtube.com", label: "legit", group: "legit-popular" },
  { url: "https://linkedin.com", label: "legit", group: "legit-popular" },
  { url: "https://cloudflare.com", label: "legit", group: "legit-popular" },
  { url: "https://cbc.ca", label: "legit", group: "legit-popular" },

  // ───────────────────────── LEGIT: obscure / non-Tranco (FP stress) ────────
  // The real false-positive test: ordinary domains NOT on any allowlist, some
  // of which are 1 edit away from a popular brand label. These MUST stay safe.
  { url: "https://mybusinesssite.ca", label: "legit", group: "legit-obscure" },
  { url: "https://torontoplumbingpros.com", label: "legit", group: "legit-obscure" },
  { url: "https://janesbakery.ca", label: "legit", group: "legit-obscure" },
  { url: "https://mature.com", label: "legit", group: "legit-obscure", note: "DL1 from 'nature' — front-loaded, must NOT match" },
  { url: "https://median.io", label: "legit", group: "legit-obscure", note: "DL1 from 'medium'" },
  { url: "https://literature.org", label: "legit", group: "legit-obscure" },
  { url: "https://signature.app", label: "legit", group: "legit-obscure" },
  { url: "https://creature.net", label: "legit", group: "legit-obscure" },
  { url: "https://smallpersonalblog.xyz", label: "legit", group: "legit-obscure" },
  { url: "https://thereturnofthething.com", label: "legit", group: "legit-obscure" }
];
