import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from '../src/auth/guards/roles.guard';
import { UserRole } from '../src/generated/prisma/client';

describe('RolesGuard (RBAC Unit Test)', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  const createMockContext = (user: any): ExecutionContext => {
    return {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
    } as unknown as ExecutionContext;
  };

  it('রোল প্রয়োজন না হলে এক্সেস দেওয়া উচিত', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(null);
    const context = createMockContext({ role: UserRole.USER });

    expect(guard.canActivate(context)).toBe(true);
  });

  it('সঠিক রোল (ADMIN) থাকলে এক্সেস অনুমোদন করা উচিত', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);
    const context = createMockContext({ role: UserRole.ADMIN });

    expect(guard.canActivate(context)).toBe(true);
  });

  it('ভুল রোল (USER role কিন্তু প্রয়োজন ADMIN) হলে 403 ForbiddenException দেওয়া উচিত', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);
    const context = createMockContext({ role: UserRole.USER });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });
});

