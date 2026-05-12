import { analyzeRequestSchema } from "@capstone/shared";
import type { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { jsonResponse } from "../services/http.js";
import { analyzeUrl } from "../services/orchestrator.js";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  if (event.requestContext.http.method === "OPTIONS") {
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
