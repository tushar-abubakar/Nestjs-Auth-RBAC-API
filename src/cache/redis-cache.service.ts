import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis, { RedisOptions } from 'ioredis';

@Injectable()
export class RedisCacheService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisCacheService.name);
  private redis: Redis | null = null;
  private _isConnected = false;
  private reconnectAttempts = 0;
  private readonly maxReconnectAttempts = 10;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const redisUrl = this.config.get<string>('cache.redis.url');
    if (!redisUrl) {
      this.logger.warn(
        'REDIS_URL not configured. Redis cache will be disabled.',
      );
      return;
    }

    const options: RedisOptions = {
      retryStrategy: (times: number): number | null => {
        if (times > this.maxReconnectAttempts) {
          this.logger.error(
            `Max reconnect attempts (${this.maxReconnectAttempts}) reached. Giving up.`,
          );
          return null;
        }
        const delay = Math.min(times * 100, 3000);
        this.logger.warn(
          `Retrying Redis connection in ${delay}ms (attempt ${times})`,
        );
        return delay;
      },
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      enableOfflineQueue: false,
      lazyConnect: false,
      keepAlive: 30000,
      connectTimeout: 10000,
      commandTimeout: 5000,
    };

    try {
      this.redis = new Redis(redisUrl, options);

      this.redis.on('connect', () => {
        this.reconnectAttempts = 0;
        this.logger.log('Redis connecting...');
      });

      this.redis.on('ready', () => {
        this._isConnected = true;
        this.logger.log('Redis ready and connected successfully');
      });

      this.redis.on('error', (error: Error) => {
        this.logger.error('Redis connection error:', error.message);
        this._isConnected = false;
      });

      this.redis.on('close', () => {
        this._isConnected = false;
        this.logger.warn('Redis connection closed');
      });

      this.redis.on('reconnecting', (delay: number) => {
        this.reconnectAttempts++;
        this.logger.log(
          `Redis reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`,
        );
      });

      this.redis.on('end', () => {
        this._isConnected = false;
        this.logger.warn('Redis connection ended');
      });

      await this.redis.ping();
      this._isConnected = true;
      this.logger.log('Redis ping successful');
    } catch (error) {
      this.logger.error(
        'Failed to initialize Redis:',
        error instanceof Error ? error.message : String(error),
      );
      this.redis = null;
      this._isConnected = false;
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.redis) {
      try {
        await this.redis.quit();
        this._isConnected = false;
        this.logger.log('Redis connection gracefully closed');
      } catch (error) {
        this.logger.error(
          'Error closing Redis connection:',
          error instanceof Error ? error.message : String(error),
        );
        try {
          this.redis.disconnect();
        } catch (disconnectError) {
          this.logger.error(
            'Error disconnecting Redis:',
            disconnectError instanceof Error
              ? disconnectError.message
              : String(disconnectError),
          );
        }
      } finally {
        this.redis = null;
      }
    }
  }

  async get<T>(key: string): Promise<T | null> {
    if (!this.redis || !this._isConnected) {
      this.logger.debug(`Redis not available for GET: ${key}`);
      return null;
    }

    try {
      const value = await this.redis.get(key);
      if (!value) return null;
      return JSON.parse(value) as T;
    } catch (error) {
      this.logger.error(
        `Failed to get cache key "${key}":`,
        error instanceof Error ? error.message : String(error),
      );
      return null;
    }
  }

  async set(key: string, value: unknown, ttlSeconds = 300): Promise<boolean> {
    if (!this.redis || !this._isConnected) {
      this.logger.debug(`Redis not available for SET: ${key}`);
      return false;
    }

    try {
      const serialized = JSON.stringify(value);
      const result = await this.redis.setex(key, ttlSeconds, serialized);
      return result === 'OK';
    } catch (error) {
      this.logger.error(
        `Failed to set cache key "${key}":`,
        error instanceof Error ? error.message : String(error),
      );
      return false;
    }
  }

  async del(key: string): Promise<boolean> {
    if (!this.redis || !this._isConnected) {
      this.logger.debug(`Redis not available for DEL: ${key}`);
      return false;
    }

    try {
      const result = await this.redis.del(key);
      return result > 0;
    } catch (error) {
      this.logger.error(
        `Failed to delete cache key "${key}":`,
        error instanceof Error ? error.message : String(error),
      );
      return false;
    }
  }

  async delPattern(pattern: string): Promise<number> {
    if (!this.redis || !this._isConnected) {
      this.logger.debug(`Redis not available for DELPATTERN: ${pattern}`);
      return 0;
    }

    try {
      // Use SCAN for production safety instead of KEYS
      let cursor = '0';
      let deletedCount = 0;
      const matchCount = 100;

      do {
        const [newCursor, keys] = await this.redis.scan(
          cursor,
          'MATCH',
          pattern,
          'COUNT',
          matchCount,
        );
        cursor = newCursor;

        if (keys.length > 0) {
          const result = await this.redis.del(...keys);
          deletedCount += result;
        }
      } while (cursor !== '0');

      if (deletedCount > 0) {
        this.logger.debug(
          `Deleted ${deletedCount} keys matching pattern: ${pattern}`,
        );
      }

      return deletedCount;
    } catch (error) {
      this.logger.error(
        `Failed to delete cache pattern "${pattern}":`,
        error instanceof Error ? error.message : String(error),
      );
      return 0;
    }
  }

  async exists(key: string): Promise<boolean> {
    if (!this.redis || !this._isConnected) return false;

    try {
      const result = await this.redis.exists(key);
      return result === 1;
    } catch (error) {
      this.logger.error(
        `Failed to check existence of key "${key}":`,
        error instanceof Error ? error.message : String(error),
      );
      return false;
    }
  }

  async ttl(key: string): Promise<number> {
    if (!this.redis || !this._isConnected) return -1;

    try {
      return await this.redis.ttl(key);
    } catch (error) {
      this.logger.error(
        `Failed to get TTL for key "${key}":`,
        error instanceof Error ? error.message : String(error),
      );
      return -1;
    }
  }

  async increment(key: string, ttlSeconds?: number): Promise<number> {
    if (!this.redis || !this._isConnected) {
      this.logger.debug(`Redis not available for INCR: ${key}`);
      return 0;
    }

    try {
      const value = await this.redis.incr(key);
      if (ttlSeconds !== undefined && value === 1) {
        await this.redis.expire(key, ttlSeconds);
      }
      return value;
    } catch (error) {
      this.logger.error(
        `Failed to increment key "${key}":`,
        error instanceof Error ? error.message : String(error),
      );
      return 0;
    }
  }

  async decrement(key: string): Promise<number> {
    if (!this.redis || !this._isConnected) {
      this.logger.debug(`Redis not available for DECR: ${key}`);
      return 0;
    }

    try {
      return await this.redis.decr(key);
    } catch (error) {
      this.logger.error(
        `Failed to decrement key "${key}":`,
        error instanceof Error ? error.message : String(error),
      );
      return 0;
    }
  }

  async mget<T>(keys: string[]): Promise<Array<T | null>> {
    if (!this.redis || !this._isConnected || keys.length === 0) {
      return keys.map(() => null);
    }

    try {
      const values = await this.redis.mget(...keys);
      return values.map((value) => (value ? (JSON.parse(value) as T) : null));
    } catch (error) {
      this.logger.error(
        `Failed to MGET keys:`,
        error instanceof Error ? error.message : String(error),
      );
      return keys.map(() => null);
    }
  }

  async mset(
    entries: Array<{ key: string; value: unknown; ttl?: number }>,
  ): Promise<boolean> {
    if (!this.redis || !this._isConnected || entries.length === 0) {
      return false;
    }

    try {
      const pipeline = this.redis.pipeline();

      for (const { key, value, ttl } of entries) {
        const serialized = JSON.stringify(value);
        if (ttl) {
          pipeline.setex(key, ttl, serialized);
        } else {
          pipeline.set(key, serialized);
        }
      }

      await pipeline.exec();
      return true;
    } catch (error) {
      this.logger.error(
        `Failed to MSET:`,
        error instanceof Error ? error.message : String(error),
      );
      return false;
    }
  }

  isConnected(): boolean {
    return (
      this._isConnected && this.redis !== null && this.redis.status === 'ready'
    );
  }

  getClient(): Redis | null {
    return this.redis;
  }

  async ping(): Promise<boolean> {
    if (!this.redis) return false;

    try {
      const result = await this.redis.ping();
      return result === 'PONG';
    } catch {
      return false;
    }
  }

  getStats(): {
    connected: boolean;
    reconnectAttempts: number;
    status: string;
  } {
    return {
      connected: this._isConnected,
      reconnectAttempts: this.reconnectAttempts,
      status: this.redis?.status ?? 'disconnected',
    };
  }
}
