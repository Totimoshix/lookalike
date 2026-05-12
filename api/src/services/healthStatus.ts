import { healthResponseSchema, type HealthResponse } from "@capstone/shared";
import { getProviderReadiness, getRuntimeConfig } from "./runtimeConfig.js";

export async function buildHealthResponse(serviceName: string): Promise<HealthResponse> {
  const [config, providers] = await Promise.all([getRuntimeConfig(), getProviderReadiness()]);

  return healthResponseSchema.parse({
    ok: true,
    service: serviceName,
    version: config.appVersion,
    stage: config.stage,
    region: config.region,
    timestamp: new Date().toISOString(),
    providers
  });
}
