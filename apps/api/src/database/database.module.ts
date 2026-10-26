import { Module } from '@nestjs/common';
import { DatabaseHealthService } from './database-health.service.js';
import { InstanceLockService } from './instance-lock.service.js';
import { PrismaService } from './prisma.service.js';

@Module({
  providers: [PrismaService, DatabaseHealthService, InstanceLockService],
  exports: [PrismaService, DatabaseHealthService, InstanceLockService],
})
export class DatabaseModule {}
