import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { RepositoriesService } from './repositories.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { ImportRepositoryDto } from './dto/import-repository.dto';

@Controller('repositories')
@UseGuards(JwtAuthGuard)
export class RepositoriesController {
  constructor(private readonly repositoriesService: RepositoriesService) {}

  /**
   * GET /repositories/github
   * Lists all repositories from connected GitHub account
   */
  @Get('github')
  async getGitHubRepositories(@GetUser('id') userId: string) {
    return this.repositoriesService.getGitHubRepositories(userId);
  }

  /**
   * POST /repositories/import
   * Imports a selected repository into TrustLayer database
   */
  @Post('import')
  async importRepository(
    @GetUser('id') userId: string,
    @Body() dto: ImportRepositoryDto,
  ) {
    return this.repositoriesService.importRepository(userId, dto);
  }

  /**
   * GET /repositories
   * Lists all repositories imported in TrustLayer by the authenticated user
   */
  @Get()
  async getUserRepositories(@GetUser('id') userId: string) {
    return this.repositoriesService.getUserRepositories(userId);
  }

  /**
   * GET /repositories/:id
   * Gets details of a specific imported repository
   */
  @Get(':id')
  async getRepositoryById(
    @GetUser('id') userId: string,
    @Param('id') id: string,
  ) {
    return this.repositoriesService.getRepositoryById(userId, id);
  }

  /**
   * DELETE /repositories/:id
   * Removes an imported repository from TrustLayer
   */
  @Delete(':id')
  async deleteRepository(
    @GetUser('id') userId: string,
    @Param('id') id: string,
  ) {
    return this.repositoriesService.deleteRepository(userId, id);
  }
}
