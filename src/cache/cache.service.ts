import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InMemoryCacheService } from './in-memory-cache.service';
import { RedisCacheService } from './redis-cache.service';

export type CacheStrategy = 'redis' | 'memory' | 'hybrid';

interface CacheHealth {
  strategy: CacheStrategy;
  redis: {
    connected: boolean;
    status: string;
  };
  memory: {
    connected: boolean;
    size: number;
    hitRate: number;
  };
}

@Injectable()
export class AppCacheService {
  private readonly logger = new Logger(AppCacheService.name);
  private readonly strategy: CacheStrategy;
  private readonly strictRedis: boolean;

  constructor(
    private readonly config: ConfigService,
    private readonly redisCache: RedisCacheService,
    private readonly memoryCache: InMemoryCacheService,
  ) {
    const nodeEnv = this.config.get<string>('app.env');
    const useRedis = this.config.get<boolean>('cache.redis.enabled');

    if (
      useRedis !== false &&
      (nodeEnv === 'production' || nodeEnv === 'staging')
    ) {
      this.strategy = 'redis';
    } else {
      this.strategy = 'memory';
    }

    this.strictRedis = nodeEnv === 'production';

    this.logger.log(
      `Cache strategy: ${this.strategy}, strict: ${this.strictRedis}`,
    );
  }

  async get<T>(key: string): Promise<T | null> {
    if (this.strategy === 'redis') {
      const value = await this.redisCache.get<T>(key);

      // Fallback to memory if Redis is down
      if (value === null && !this.redisCache.isConnected()) {
        this.logger.warn(
          `Redis unavailable for GET ${key}, falling back to memory`,
        );
        return this.memoryCache.get<T>(key);
      }
      return value;
    }

    return this.memoryCache.get<T>(key);
  }

  async set(key: string, value: unknown, ttlSeconds = 300): Promise<void> {
    if (this.strategy === 'redis') {
      const success = await this.redisCache.set(key, value, ttlSeconds);

      if (!success) {
        this.logger.warn(`Redis SET failed for ${key}, falling back to memory`);
        this.memoryCache.set(key, value, ttlSeconds);
      }
      return;
    }

    this.memoryCache.set(key, value, ttlSeconds);
  }

  async del(key: string): Promise<void> {
    if (this.strategy === 'redis') {
      const success = await this.redisCache.del(key);

      if (!success) {
        this.logger.warn(`Redis DEL failed for ${key}, falling back to memory`);
        this.memoryCache.del(key);
      }
      return;
    }

    this.memoryCache.del(key);
  }

  async delPattern(pattern: string): Promise<void> {
    if (this.strategy === 'redis') {
      const count = await this.redisCache.delPattern(pattern);

      if (count === 0 && !this.redisCache.isConnected()) {
        this.logger.warn(
          `Redis DELPATTERN failed for ${pattern}, falling back to memory`,
        );
        this.memoryCache.delPattern(pattern);
      }
      return;
    }

    this.memoryCache.delPattern(pattern);
  }

  async exists(key: string): Promise<boolean> {
    if (this.strategy === 'redis') {
      if (!this.redisCache.isConnected()) {
        return this.memoryCache.exists(key);
      }
      return this.redisCache.exists(key);
    }

    return this.memoryCache.exists(key);
  }

  async ttl(key: string): Promise<number> {
    if (this.strategy === 'redis') {
      if (!this.redisCache.isConnected()) {
        return this.memoryCache.ttl(key);
      }
      return this.redisCache.ttl(key);
    }

    return this.memoryCache.ttl(key);
  }

  async increment(key: string, ttlSeconds?: number): Promise<number> {
    if (this.strategy === 'redis') {
      const value = await this.redisCache.increment(key, ttlSeconds);

      if (value === 0 && !this.redisCache.isConnected()) {
        this.logger.warn(
          `Redis INCR failed for ${key}, falling back to memory`,
        );
        return this.memoryCache.increment(key, ttlSeconds);
      }
      return value;
    }

    return this.memoryCache.increment(key, ttlSeconds);
  }

  async decrement(key: string): Promise<number> {
    if (this.strategy === 'redis') {
      const value = await this.redisCache.decrement(key);

      if (value === 0 && !this.redisCache.isConnected()) {
        this.logger.warn(
          `Redis DECR failed for ${key}, falling back to memory`,
        );
        return this.memoryCache.decrement(key);
      }
      return value;
    }

    return this.memoryCache.decrement(key);
  }

  async mget<T>(keys: string[]): Promise<Array<T | null>> {
    if (this.strategy === 'redis') {
      if (!this.redisCache.isConnected()) {
        return this.memoryCache.mget<T>(keys);
      }
      return this.redisCache.mget<T>(keys);
    }

    return this.memoryCache.mget<T>(keys);
  }

  async mset(
    entries: Array<{ key: string; value: unknown; ttl?: number }>,
  ): Promise<void> {
    if (this.strategy === 'redis') {
      const success = await this.redisCache.mset(entries);

      if (!success) {
        this.logger.warn('Redis MSET failed, falling back to memory');
        this.memoryCache.mset(entries);
      }
      return;
    }

    this.memoryCache.mset(entries);
  }

  isConnected(): boolean {
    if (this.strategy === 'redis') {
      return this.redisCache.isConnected();
    }
    return this.memoryCache.isConnected();
  }

  getStrategy(): CacheStrategy {
    return this.strategy;
  }

  getHealth(): CacheHealth {
    const redisStats = this.redisCache.getStats();
    const memoryStats = this.memoryCache.getStats();

    return {
      strategy: this.strategy,
      redis: {
        connected: redisStats.connected,
        status: redisStats.status,
      },
      memory: {
        connected: this.memoryCache.isConnected(),
        size: memoryStats.size,
        hitRate: memoryStats.hitRate,
      },
    };
  }

  async ping(): Promise<{ redis: boolean; memory: boolean }> {
    return {
      redis: await this.redisCache.ping(),
      memory: this.memoryCache.isConnected(),
    };
  }

  getRedisCache(): RedisCacheService {
    return this.redisCache;
  }

  getMemoryCache(): InMemoryCacheService {
    return this.memoryCache;
  }
}
