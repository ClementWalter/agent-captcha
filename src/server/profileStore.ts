/**
 * Durable agent profile storage on Scaleway Object Storage.
 *
 * Why: self-sovereign agent identity means the agentId is a long hex key.
 * Profiles let an agent pick a human-readable display name — still gated by
 * the full agent-captcha protocol (CommitLLM receipt + Ed25519 signature),
 * so a display name change IS a real verified LLM inference, not a free
 * rename. One object per agentId, overwrite-in-place.
 */
import { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import pino from "pino";

const logger = pino({ name: "agent-captcha-profile-store" });

export interface AgentProfile {
  agentId: string;
  displayName: string;
  updatedAt: string;
  lastCommitHash: string;
}

export interface ProfileStore {
  upsert(profile: AgentProfile): Promise<void>;
  getMany(agentIds: string[]): Promise<Record<string, AgentProfile>>;
  listAll(): Promise<Record<string, AgentProfile>>;
  healthCheck(): Promise<void>;
}

export interface S3ProfileStoreConfig {
  endpoint: string;
  bucket: string;
  region: string;
  accessKey: string;
  secretKey: string;
  keyPrefix?: string;
}

export class S3ProfileStore implements ProfileStore {
  private readonly client: S3Client;
  private readonly bucket: string;
  private readonly prefix: string;

  public constructor(config: S3ProfileStoreConfig) {
    this.client = new S3Client({
      endpoint: config.endpoint,
      region: config.region,
      credentials: { accessKeyId: config.accessKey, secretAccessKey: config.secretKey },
      forcePathStyle: true
    });
    this.bucket = config.bucket;
    this.prefix = config.keyPrefix ?? "profiles/";
  }

  public async upsert(profile: AgentProfile): Promise<void> {
    const key = `${this.prefix}${profile.agentId}.json`;
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: JSON.stringify(profile),
        ContentType: "application/json"
      })
    );
    logger.info({ key, agentId: profile.agentId, displayName: profile.displayName }, "profile upserted");
  }

  public async getMany(agentIds: string[]): Promise<Record<string, AgentProfile>> {
    const unique = Array.from(new Set(agentIds));
    const entries = await Promise.all(
      unique.map(async (agentId) => {
        try {
          const response = await this.client.send(
            new GetObjectCommand({ Bucket: this.bucket, Key: `${this.prefix}${agentId}.json` })
          );
          const body = await response.Body?.transformToString();
          if (!body) {
            return null;
          }
          return JSON.parse(body) as AgentProfile;
        } catch (error) {
          // Missing profile is normal — agent just hasn't set a name yet.
          const name = (error as { name?: string } | null)?.name;
          if (name !== "NoSuchKey") {
            logger.warn({ err: error, agentId }, "profile fetch failed");
          }
          return null;
        }
      })
    );
    const result: Record<string, AgentProfile> = {};
    for (const profile of entries) {
      if (profile) {
        result[profile.agentId] = profile;
      }
    }
    return result;
  }

  public async listAll(): Promise<Record<string, AgentProfile>> {
    const profiles: Record<string, AgentProfile> = {};
    let token: string | undefined;
    do {
      const response = await this.client.send(
        new ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: this.prefix,
          ContinuationToken: token,
          MaxKeys: 1000
        })
      );
      const keys = (response.Contents ?? [])
        .map((e) => e.Key)
        .filter((k): k is string => typeof k === "string");
      const fetched = await Promise.all(
        keys.map(async (key) => {
          const resp = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
          const body = await resp.Body?.transformToString();
          return body ? (JSON.parse(body) as AgentProfile) : null;
        })
      );
      for (const profile of fetched) {
        if (profile) {
          profiles[profile.agentId] = profile;
        }
      }
      token = response.IsTruncated ? response.NextContinuationToken : undefined;
    } while (token);
    return profiles;
  }

  public async healthCheck(): Promise<void> {
    await this.client.send(
      new ListObjectsV2Command({ Bucket: this.bucket, Prefix: this.prefix, MaxKeys: 1 })
    );
  }
}

export function createProfileStoreFromEnv(): ProfileStore {
  const endpoint = process.env.S3_ENDPOINT;
  const bucket = process.env.S3_BUCKET;
  const region = process.env.S3_REGION;
  const accessKey = process.env.S3_ACCESS_KEY;
  const secretKey = process.env.S3_SECRET_KEY;
  if (!endpoint || !bucket || !region || !accessKey || !secretKey) {
    throw new Error(
      "profile_store_misconfigured: S3_ENDPOINT, S3_BUCKET, S3_REGION, S3_ACCESS_KEY, S3_SECRET_KEY are all required"
    );
  }
  return new S3ProfileStore({ endpoint, bucket, region, accessKey, secretKey });
}
