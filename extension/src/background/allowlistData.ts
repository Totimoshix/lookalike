// Re-export the Tranco top-10k list from the shared workspace. Both the
// extension SW (this allowlist) and the API brand matcher use the same
// underlying data. Regenerate with `npm run build:allowlist`.

import { TRANCO_DOMAINS } from "@capstone/shared";

export const ALLOWLIST_DOMAINS: readonly string[] = TRANCO_DOMAINS;
