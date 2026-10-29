import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class DashboardService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Main dashboard summary metrics for authenticated user
   */
  async getDashboardSummary(userId: string) {
    // 1. Total Repositories
    const totalRepositories = await this.prisma.repository.count({
      where: { userId },
    });

    // 2. Total Scans executed
    const totalScans = await this.prisma.scan.count({
      where: { userId },
    });

    // 3. Scan counts by status
    const scansByStatus = await this.prisma.scan.groupBy({
      by: ['status'],
      where: { userId },
      _count: { _all: true },
    });

    // 4. All findings across all user scans
    const findings = await this.prisma.finding.findMany({
      where: {
        scan: { userId },
      },
      select: {
        id: true,
        severity: true,
        status: true,
        createdAt: true,
      },
    });

    const findingsSeverityCount = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };

    const findingsStatusCount = {
      OPEN: 0,
      RESOLVED: 0,
      IGNORED: 0,
    };

    for (const f of findings) {
      if (findingsSeverityCount[f.severity] !== undefined) {
        findingsSeverityCount[f.severity]++;
      }
      if (findingsStatusCount[f.status] !== undefined) {
        findingsStatusCount[f.status]++;
      }
    }

    // 5. Average Risk Score calculation
    const completedScans = await this.prisma.scan.findMany({
      where: {
        userId,
        status: 'COMPLETED',
        riskScore: { not: null },
      },
      select: { riskScore: true },
    });

    const averageRiskScore =
      completedScans.length > 0
        ? Math.round(
            completedScans.reduce((acc, s) => acc + (s.riskScore || 0), 0) /
              completedScans.length,
          )
        : 0;

    // 6. Recent 5 Scans
    const recentScans = await this.prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 5,
      include: {
        repository: {
          select: { id: true, name: true, fullName: true },
        },
        _count: {
          select: { findings: true },
        },
      },
    });

    // 7. Recent 5 Critical or High Open Findings
    const topVulnerabilities = await this.prisma.finding.findMany({
      where: {
        scan: { userId },
        status: 'OPEN',
        severity: { in: ['CRITICAL', 'HIGH'] },
      },
      orderBy: { createdAt: 'desc' },
      take: 5,
      include: {
        scan: {
          select: {
            id: true,
            repository: {
              select: { name: true, fullName: true },
            },
          },
        },
      },
    });

    return {
      metrics: {
        totalRepositories,
        totalScans,
        averageRiskScore,
        totalFindings: findings.length,
        openFindings: findingsStatusCount.OPEN,
        resolvedFindings: findingsStatusCount.RESOLVED,
      },
      severityBreakdown: findingsSeverityCount,
      statusBreakdown: findingsStatusCount,
      scansStatusBreakdown: scansByStatus.reduce((acc, curr) => {
        acc[curr.status] = curr._count._all;
        return acc;
      }, {} as Record<string, number>),
      recentScans,
      topVulnerabilities,
    };
  }
}
