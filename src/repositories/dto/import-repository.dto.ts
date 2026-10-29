import { IsNotEmpty, IsString, IsBoolean, IsOptional } from 'class-validator';

export class ImportRepositoryDto {
  @IsNotEmpty()
  @IsString()
  githubId: string;

  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  fullName: string;

  @IsNotEmpty()
  @IsString()
  url: string;

  @IsOptional()
  @IsBoolean()
  private?: boolean;
}
