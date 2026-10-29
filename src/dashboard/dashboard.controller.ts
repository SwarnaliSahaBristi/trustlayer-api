import { Controller, Get, UseGuards } from '@nestjs/common';
import { DashboardService } from './dashboard.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';

@Controller('dashboard')
@UseGuards(JwtAuthGuard)
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  /**
   * GET /dashboard/summary
   * Aggregates total repositories, scan counts, risk score, findings, and trends
   */
  @Get('summary')
  async getDashboardSummary(@GetUser('id') userId: string) {
    return this.dashboardService.getDashboardSummary(userId);
  }
}
