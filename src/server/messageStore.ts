/**
 * Durable message storage backed by Scaleway Object Storage (S3-compatible).
 *
 * Why: serverless containers are stateless — every redeploy or cold start
 * discards in-memory state. Messages are sensitive user-visible data and
 * must survive deploys. One object per message, so appends never race and
 * no message is ever silently overwritten by another's write.
 *
 * Key layout:
 *   messages/<iso-timestamp>-<uuid>.json
 *
 * The ISO-timestamp prefix keeps an ordered listing (S3 ListObjectsV2
 * returns keys lexicographically). That lets GET /api/messages return the
 * thread in chronological order without sorting in the client.
 */
import {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
  GetObjectCommand
} from "@aws-sdk/client-s3";
import pino from "pino";
import type { ChatMessage } from "./app";

const logger = pino({ name: "agent-captcha-message-store" });

export interface MessageStore {
  append(message: ChatMessage): Promise<void>;
  list(): Promise<ChatMessage[]>;
  healthCheck(): Promise<void>;
}

export interface S3MessageStoreConfig {
  endpoint: string;
  bucket: string;
  region: string;
  accessKey: string;
  secretKey: string;
  keyPrefix?: string;
}

export class S3MessageStore implements MessageStore {
  private readonly client: S3Client;
  private readonly bucket: string;
  private readonly prefix: string;

  public constructor(config: S3MessageStoreConfig) {
    this.client = new S3Client({
      endpoint: config.endpoint,
      region: config.region,
      credentials: {
        accessKeyId: config.accessKey,
        secretAccessKey: config.secretKey
      },
      // Scaleway uses path-style addressing compatibly with virtual-hosted,
      // but forcePathStyle=true avoids DNS/vhost surprises on cold bootstraps.
      forcePathStyle: true
    });
    this.bucket = config.bucket;
    this.prefix = config.keyPrefix ?? "messages/";
  }

  public async append(message: ChatMessage): Promise<void> {
    // Stable lexicographic ordering on the prefix — `createdAt` is an ISO-8601
    // timestamp so listing keys in order gives us thread order for free.
    const key = `${this.prefix}${message.createdAt}-${message.id}.json`;
    const body = JSON.stringify(message);
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: "application/json"
      })
    );
    logger.info({ key, messageId: message.id }, "message persisted");
  }

  public async list(): Promise<ChatMessage[]> {
    const messages: ChatMessage[] = [];
    let continuationToken: string | undefined;

    do {
      const response = await this.client.send(
        new ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: this.prefix,
          ContinuationToken: continuationToken,
          MaxKeys: 1000
        })
      );

      const keys = (response.Contents ?? [])
        .map((entry) => entry.Key)
        .filter((key): key is string => typeof key === "string");

      // Fan out the GETs — each object is small (a few hundred bytes), so
      // parallelism is cheap and the total wall time stays low even with
      // hundreds of messages.
      const fetched = await Promise.all(keys.map((key) => this.readMessage(key)));
      for (const message of fetched) {
        if (message) {
          messages.push(message);
        }
      }

      continuationToken = response.IsTruncated ? response.NextContinuationToken : undefined;
    } while (continuationToken);

    return messages;
  }

  public async healthCheck(): Promise<void> {
    // A 0-byte list call is enough to confirm the bucket is reachable and
    // the credentials are scoped to read it. Used at boot so a misconfigured
    // container fails fast instead of serving a silent empty thread.
    await this.client.send(
      new ListObjectsV2Command({
        Bucket: this.bucket,
        Prefix: this.prefix,
        MaxKeys: 1
      })
    );
  }

  private async readMessage(key: string): Promise<ChatMessage | null> {
    try {
      const response = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: key })
      );
      const bodyText = await response.Body?.transformToString();
      if (!bodyText) {
        return null;
      }
      return JSON.parse(bodyText) as ChatMessage;
    } catch (error) {
      // A missing or corrupted object should not take down the whole thread —
      // log and drop. If this becomes common we should add quarantine logic.
      logger.warn({ err: error, key }, "failed to read message object");
      return null;
    }
  }
}

export function createMessageStoreFromEnv(): MessageStore {
  const endpoint = process.env.S3_ENDPOINT;
  const bucket = process.env.S3_BUCKET;
  const region = process.env.S3_REGION;
  const accessKey = process.env.S3_ACCESS_KEY;
  const secretKey = process.env.S3_SECRET_KEY;

  if (!endpoint || !bucket || !region || !accessKey || !secretKey) {
    throw new Error(
      "message_store_misconfigured: S3_ENDPOINT, S3_BUCKET, S3_REGION, S3_ACCESS_KEY, S3_SECRET_KEY are all required"
    );
  }

  return new S3MessageStore({ endpoint, bucket, region, accessKey, secretKey });
}
