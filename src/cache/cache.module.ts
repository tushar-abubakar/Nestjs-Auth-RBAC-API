import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppCacheService } from './cache.service';
import { InMemoryCacheService } from './in-memory-cache.service';
import { RedisCacheService } from './redis-cache.service';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [InMemoryCacheService, RedisCacheService, AppCacheService],
  exports: [AppCacheService, InMemoryCacheService, RedisCacheService],
})
export class AppCacheModule {}
