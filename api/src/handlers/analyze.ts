import { analyzeRequestSchema } from "@capstone/shared";
import type { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { jsonResponse } from "../services/http.js";
import { analyzeUrl } from "../services/orchestrator.js";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Scheduled warmer pings (EventBridge) keep the Lambda hot — short-circuit
  // before any work or schema parsing.
  if ((event as unknown as { warmup?: boolean }).warmup === true) {
    return jsonResponse(200, { warm: true });
  }
  // Tolerate both API Gateway payload formats: REST API (v1) exposes
  // event.httpMethod; HTTP API (v2) exposes event.requestContext.http.method.
  const evt = event as unknown as {
    httpMethod?: string;
    requestContext?: { http?: { method?: string } };
  };
  const method = evt.httpMethod ?? evt.requestContext?.http?.method;
  if (method === "OPTIONS") {
    return jsonResponse(204, {});
  }

  try {
    const parsed = analyzeRequestSchema.parse(JSON.parse(event.body ?? "{}"));
    const result = await analyzeUrl(parsed);
    return jsonResponse(200, result);
  } catch (error) {
    return jsonResponse(400, {
      message: error instanceof Error ? error.message : "Invalid request"
    });
  }
};
