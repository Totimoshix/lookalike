import { generateLookalikesRequestSchema } from "@capstone/shared";
import type { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { jsonResponse } from "../services/http.js";
import { generateLookalikeSet } from "../services/orchestrator.js";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  if (event.requestContext.http.method === "OPTIONS") {
    return jsonResponse(204, {});
  }

  try {
    const parsed = generateLookalikesRequestSchema.parse(JSON.parse(event.body ?? "{}"));
    const result = await generateLookalikeSet(parsed);
    return jsonResponse(200, result);
  } catch (error) {
    return jsonResponse(400, {
      message: error instanceof Error ? error.message : "Invalid request"
    });
  }
};
