import { BedrockRuntimeClient, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import { getRuntimeConfig } from "./runtimeConfig.js";

type BedrockJsonCall<T> = {
  promptName: string;
  prompt: string;
  validator: (value: unknown) => T | null;
};

let client: BedrockRuntimeClient | null = null;
let clientRegion: string | null = null;

function getClient(region: string): BedrockRuntimeClient {
  if (!client || clientRegion !== region) {
    client = new BedrockRuntimeClient({
      region
    });
    clientRegion = region;
  }
  return client;
}

function tryParseJson(text: string): unknown {
  const trimmed = text.trim().replace(/^```json/i, "").replace(/^```/, "").replace(/```$/, "").trim();
  return JSON.parse(trimmed);
}

export async function callBedrockJson<T>({ prompt, validator }: BedrockJsonCall<T>): Promise<T | null> {
  const config = await getRuntimeConfig();
  const modelId = config.bedrockModelId;
  if (!modelId) {
    return null;
  }

  try {
    const response = await getClient(config.bedrockRegion).send(
      new ConverseCommand({
        modelId,
        messages: [
          {
            role: "user",
            content: [{ text: prompt }]
          }
        ],
        inferenceConfig: {
          maxTokens: 1000,
          temperature: 0.2
        }
      })
    );

    const content = response.output?.message?.content
      ?.map((part) => ("text" in part && part.text ? part.text : ""))
      .join("\n");
    if (!content) {
      return null;
    }

    return validator(tryParseJson(content));
  } catch {
    return null;
  }
}
