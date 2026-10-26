import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AccountSecurityController } from '../account/account-security.controller.js';
import { AccountSecurityService } from '../account/account-security.service.js';
import { AccountController } from '../account/account.controller.js';
import { DatabaseModule } from '../database/database.module.js';
import { MaintenanceService } from '../maintenance/maintenance.service.js';
import { PairingController } from '../pairing/pairing.controller.js';
import { PairingService } from '../pairing/pairing.service.js';
import { RecoveryController } from '../recovery/recovery.controller.js';
import { RecoveryService } from '../recovery/recovery.service.js';
import { SecurityEventsService } from '../security-events/security-events.service.js';
import { AccessGuard } from '../sessions/access.guard.js';
import { SessionService } from '../sessions/session.service.js';
import { SyncService } from '../vault/sync.service.js';
import { VaultController } from '../vault/vault.controller.js';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { LoginStateStore } from './login-state.store.js';
import { OpaqueServerService } from './opaque-server.service.js';
import { ThrottleService } from './throttle.service.js';

/** Authentication, sessions, account and vault endpoints, behind the global access guard. */
@Module({
  imports: [DatabaseModule],
  controllers: [
    AuthController,
    AccountController,
    VaultController,
    PairingController,
    RecoveryController,
    AccountSecurityController,
  ],
  providers: [
    AuthService,
    MaintenanceService,
    OpaqueServerService,
    SessionService,
    LoginStateStore,
    ThrottleService,
    SecurityEventsService,
    SyncService,
    PairingService,
    RecoveryService,
    AccountSecurityService,
    { provide: APP_GUARD, useClass: AccessGuard },
  ],
  exports: [SessionService, SecurityEventsService, ThrottleService],
})
export class AuthModule {}
