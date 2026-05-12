import type { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { jsonResponse } from "../services/http.js";
import { buildHealthResponse } from "../services/healthStatus.js";

export const handler: APIGatewayProxyHandlerV2 = async () =>
  jsonResponse(200, await buildHealthResponse("capstone-domain-guardian-api"));
