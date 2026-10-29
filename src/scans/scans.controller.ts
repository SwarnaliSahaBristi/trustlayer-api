import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ScansService } from './scans.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';

@Controller('scans')
@UseGuards(JwtAuthGuard)
export class ScansController {
  constructor(private readonly scansService: ScansService) {}

  /**
   * POST /scans/:repositoryId
   * Trigger a new scan for a repository
   */
  @Post(':repositoryId')
  async triggerScan(
    @GetUser('id') userId: string,
    @Param('repositoryId') repositoryId: string,
  ) {
    return this.scansService.triggerScan(userId, repositoryId);
  }

  /**
   * GET /scans/recent
   * View recent scans across all repositories
   */
  @Get('recent')
  async getRecentScans(@GetUser('id') userId: string) {
    return this.scansService.getRecentScans(userId);
  }

  /**
   * GET /scans/:scanId
   * Get real-time status, risk score, and deep findings of a scan
   */
  @Get(':scanId')
  async getScanById(
    @GetUser('id') userId: string,
    @Param('scanId') scanId: string,
  ) {
    return this.scansService.getScanById(userId, scanId);
  }

  /**
   * GET /scans/repository/:repositoryId
   * Get all past scans for a specific repository
   */
  @Get('repository/:repositoryId')
  async getScansByRepository(
    @GetUser('id') userId: string,
    @Param('repositoryId') repositoryId: string,
  ) {
    return this.scansService.getScansByRepository(userId, repositoryId);
  }

  /**
   * PATCH /scans/findings/:findingId/status
   * Mark a finding as RESOLVED or IGNORED
   */
  @Patch('findings/:findingId/status')
  async updateFindingStatus(
    @GetUser('id') userId: string,
    @Param('findingId') findingId: string,
    @Body('status') status: 'OPEN' | 'RESOLVED' | 'IGNORED',
  ) {
    return this.scansService.updateFindingStatus(userId, findingId, status);
  }

  /**
   * POST /scans/findings/:findingId/ai-explain
   * Generate or re-generate AI explanation and suggestions for a specific finding
   */
  @Post('findings/:findingId/ai-explain')
  async explainFinding(
    @GetUser('id') userId: string,
    @Param('findingId') findingId: string,
  ) {
    return this.scansService.explainFindingOnDemand(userId, findingId);
  }
}
