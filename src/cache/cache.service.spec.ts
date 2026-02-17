import { ConfigModule } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { AppCacheService } from './cache.service';
import { InMemoryCacheService } from './in-memory-cache.service';
import { RedisCacheService } from './redis-cache.service';

describe('CacheService', () => {
  let service: AppCacheService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [ConfigModule],
      providers: [
        AppCacheService,
        InMemoryCacheService,
        RedisCacheService,
        AppCacheService,
      ],
    }).compile();

    service = module.get<AppCacheService>(AppCacheService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
