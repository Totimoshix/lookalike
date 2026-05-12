import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import type { AnalysisResult } from "@capstone/shared";

type CacheRecord = {
  cache_key: string;
  expires_at: number;
  payload: AnalysisResult;
};

const localCache = new Map<string, CacheRecord>();

export class AnalysisCache {
  private documentClient: DynamoDBDocumentClient | null;

  constructor(private readonly tableName = process.env.CACHE_TABLE_NAME) {
    this.documentClient = this.tableName
      ? DynamoDBDocumentClient.from(new DynamoDBClient({}))
      : null;
  }

  async get(cacheKey: string): Promise<AnalysisResult | null> {
    const local = localCache.get(cacheKey);
    const now = Math.floor(Date.now() / 1000);
    if (local && local.expires_at > now) {
      return local.payload;
    }

    if (!this.documentClient || !this.tableName) {
      return null;
    }

    const response = await this.documentClient.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { cache_key: cacheKey }
      })
    );
    const item = response.Item as CacheRecord | undefined;
    if (!item) {
      return null;
    }
    if (item.expires_at <= now) {
      await this.documentClient.send(
        new DeleteCommand({
          TableName: this.tableName,
          Key: { cache_key: cacheKey }
        })
      );
      return null;
    }
    localCache.set(cacheKey, item);
    return item.payload;
  }

  async set(cacheKey: string, payload: AnalysisResult, ttlSeconds = 3600): Promise<void> {
    const record: CacheRecord = {
      cache_key: cacheKey,
      expires_at: Math.floor(Date.now() / 1000) + ttlSeconds,
      payload
    };

    localCache.set(cacheKey, record);

    if (!this.documentClient || !this.tableName) {
      return;
    }

    await this.documentClient.send(
      new PutCommand({
        TableName: this.tableName,
        Item: record
      })
    );
  }
}

