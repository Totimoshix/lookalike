import type {
  AnalysisResult,
  AnalyzeRequest,
  GenerateLookalikesRequest,
  LookalikeCandidateSet
} from "@capstone/shared";
import { getApiBaseUrl } from "./storage";

const DEFAULT_API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:3000";

async function resolveApiBaseUrl(): Promise<string> {
  try {
    const override = await getApiBaseUrl();
    if (override) return override;
  } catch {
    // fall through
  }
  return DEFAULT_API_BASE_URL;
}

function buildNonJsonApiError(apiBaseUrl: string, bodyPreview: string): Error {
  if (/burp suite professional/i.test(bodyPreview) || /<title>burp suite/i.test(bodyPreview)) {
    return new Error(
      `Port 3000 is serving Burp instead of the Capstone API. Stop or move the Burp listener, run 'npm run start', and reload the extension.`
    );
  }

  return new Error(`API at ${apiBaseUrl} returned non-JSON content: ${bodyPreview}`);
}

async function postJson<TResponse, TRequest>(path: string, payload: TRequest, options?: { signal?: AbortSignal }): Promise<TResponse> {
  const apiBaseUrl = await resolveApiBaseUrl();
  let response: Response;

  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(payload),
      signal: options?.signal
    });
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(`API unreachable at ${apiBaseUrl}. Start 'npm run start:api' and reload the extension.`);
    }
    throw error;
  }

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => null)) as { message?: string } | null;
    throw new Error(errorBody?.message ?? `Request failed with status ${response.status}`);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    const bodyPreview = (await response.text()).slice(0, 120);
    throw buildNonJsonApiError(apiBaseUrl, bodyPreview);
  }

  try {
    return (await response.json()) as TResponse;
  } catch {
    throw new Error(`API at ${apiBaseUrl} returned invalid JSON. Reload the extension after rebuilding and confirm the local API is running.`);
  }
}

export function analyzeDomain(request: AnalyzeRequest) {
  return postJson<AnalysisResult, AnalyzeRequest>("/analyze", request);
}

export function analyzeDomainFast(request: AnalyzeRequest, signal?: AbortSignal) {
  return postJson<AnalysisResult, AnalyzeRequest>("/analyze/fast", request, { signal });
}

export function generateLookalikes(request: GenerateLookalikesRequest) {
  return postJson<LookalikeCandidateSet, GenerateLookalikesRequest>("/generate-lookalikes", request);
}
