import { analyzeRequestSchema } from "@capstone/shared";
import type { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { jsonResponse } from "../services/http.js";
import { analyzeUrlFast } from "../services/fastOrchestrator.js";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
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
    const result = await analyzeUrlFast(parsed);
    return jsonResponse(200, result);
  } catch (error) {
    return jsonResponse(400, {
      message: error instanceof Error ? error.message : "Invalid request"
    });
  }
};
