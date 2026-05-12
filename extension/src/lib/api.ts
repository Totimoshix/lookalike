import type {
  AnalysisResult,
  AnalyzeRequest,
  GenerateLookalikesRequest,
  LookalikeCandidateSet
} from "@capstone/shared";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:3000";

function buildNonJsonApiError(apiBaseUrl: string, bodyPreview: string): Error {
  if (/burp suite professional/i.test(bodyPreview) || /<title>burp suite/i.test(bodyPreview)) {
    return new Error(
      `Port 3000 is serving Burp instead of the Capstone API. Stop or move the Burp listener, run 'npm run start', and reload the extension.`
    );
  }

  return new Error(`API at ${apiBaseUrl} returned non-JSON content: ${bodyPreview}`);
}

async function postJson<TResponse, TRequest>(path: string, payload: TRequest): Promise<TResponse> {
  let response: Response;

  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(payload)
    });
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(`API unreachable at ${API_BASE_URL}. Start 'npm run start:api' and reload the extension.`);
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
    throw buildNonJsonApiError(API_BASE_URL, bodyPreview);
  }

  try {
    return (await response.json()) as TResponse;
  } catch {
    throw new Error(`API at ${API_BASE_URL} returned invalid JSON. Reload the extension after rebuilding and confirm the local API is running.`);
  }
}

export function analyzeDomain(request: AnalyzeRequest) {
  return postJson<AnalysisResult, AnalyzeRequest>("/analyze", request);
}

export function generateLookalikes(request: GenerateLookalikesRequest) {
  return postJson<LookalikeCandidateSet, GenerateLookalikesRequest>("/generate-lookalikes", request);
}
