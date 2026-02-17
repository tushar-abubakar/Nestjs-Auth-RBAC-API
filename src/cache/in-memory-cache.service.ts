import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
  createdAt: number;
  accessCount: number;
  lastAccessedAt: number;
}

interface CacheStats {
  size: number;
  keys: string[];
  oldestEntry: number | null;
  newestEntry: number | null;
  totalAccessCount: number;
  hitRate: number;
  memoryUsageEstimate: number;
}

@Injectable()
export class InMemoryCacheService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(InMemoryCacheService.name);
  private readonly cache: Map<string, CacheEntry<unknown>>;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private readonly maxSize: number;
  private hits = 0;
  private misses = 0;

  constructor(private readonly config: ConfigService) {
    this.cache = new Map();
    this.maxSize = this.config.get<number>('cache.max', 1000);
  }

  onModuleInit(): void {
    const cleanupIntervalMs = this.config.get<number>(
      'cache.cleanupInterval',
      5 * 60 * 1000,
    );

    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, cleanupIntervalMs);

    this.logger.log(
      `In-memory cache initialized (max: ${this.maxSize}, cleanup: ${cleanupIntervalMs}ms)`,
    );
  }

  onModuleDestroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.cache.clear();
    this.logger.log('In-memory cache destroyed and cleared');
  }

  get<T>(key: string): T | null {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined;

    if (!entry) {
      this.misses++;
      return null;
    }

    const now = Date.now();
    if (now > entry.expiresAt) {
      this.cache.delete(key);
      this.misses++;
      return null;
    }

    // Update access statistics
    entry.accessCount++;
    entry.lastAccessedAt = now;
    this.hits++;

    return entry.data;
  }

  set(key: string, value: unknown, ttlSeconds = 300): void {
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;

    // Evict if cache is full
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      this.evictLRU();
    }

    this.cache.set(key, {
      data: value,
      expiresAt,
      createdAt: now,
      accessCount: 0,
      lastAccessedAt: now,
    });
  }

  del(key: string): void {
    this.cache.delete(key);
  }

  delPattern(pattern: string): void {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    const keysToDelete: string[] = [];

    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        keysToDelete.push(key);
      }
    }

    keysToDelete.forEach((key) => this.cache.delete(key));

    if (keysToDelete.length > 0) {
      this.logger.debug(
        `Deleted ${keysToDelete.length} keys matching pattern: ${pattern}`,
      );
    }
  }

  exists(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;

    const now = Date.now();
    if (now > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  ttl(key: string): number {
    const entry = this.cache.get(key);
    if (!entry) return -2; // Key doesn't exist

    const now = Date.now();
    if (now > entry.expiresAt) {
      this.cache.delete(key);
      return -2;
    }

    return Math.ceil((entry.expiresAt - now) / 1000);
  }

  increment(key: string, ttlSeconds?: number): number {
    const current = this.get<number>(key);
    const newValue = (current ?? 0) + 1;

    let ttl = ttlSeconds;
    if (ttl === undefined) {
      const existingTtl = this.ttl(key);
      ttl = existingTtl > 0 ? existingTtl : 300;
    }

    this.set(key, newValue, ttl);
    return newValue;
  }

  decrement(key: string): number {
    const current = this.get<number>(key);
    const newValue = Math.max(0, (current ?? 0) - 1);

    const ttl = this.ttl(key);
    this.set(key, newValue, ttl > 0 ? ttl : 300);

    return newValue;
  }

  mget<T>(keys: string[]): Array<T | null> {
    return keys.map((key) => this.get<T>(key));
  }

  mset(entries: Array<{ key: string; value: unknown; ttl?: number }>): void {
    for (const { key, value, ttl } of entries) {
      this.set(key, value, ttl ?? 300);
    }
  }

  isConnected(): boolean {
    return true; // Memory cache is always available
  }

  clear(): void {
    const size = this.cache.size;
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
    this.logger.log(`Cache manually cleared (${size} entries removed)`);
  }

  size(): number {
    return this.cache.size;
  }

  private cleanup(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      this.logger.debug(
        `Cleaned up ${cleanedCount} expired entries (${this.cache.size} remaining)`,
      );
    }
  }

  private evictLRU(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccessedAt < oldestTime) {
        oldestTime = entry.lastAccessedAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
      this.logger.debug(`Evicted LRU entry: ${oldestKey}`);
    }
  }

  getStats(): CacheStats {
    const keys = Array.from(this.cache.keys());
    const entries = Array.from(this.cache.values());

    const expirations = entries.map((e) => e.expiresAt);
    const totalAccess = entries.reduce((sum, e) => sum + e.accessCount, 0);
    const totalRequests = this.hits + this.misses;
    const hitRate = totalRequests > 0 ? this.hits / totalRequests : 0;

    // Rough memory estimate
    const avgKeySize = 50; // Average key size in bytes
    const avgValueSize = 200; // Average value size in bytes
    const memoryUsageEstimate = this.cache.size * (avgKeySize + avgValueSize);

    return {
      size: this.cache.size,
      keys,
      oldestEntry: expirations.length ? Math.min(...expirations) : null,
      newestEntry: expirations.length ? Math.max(...expirations) : null,
      totalAccessCount: totalAccess,
      hitRate: Math.round(hitRate * 100) / 100,
      memoryUsageEstimate,
    };
  }

  resetStats(): void {
    this.hits = 0;
    this.misses = 0;
  }
}
