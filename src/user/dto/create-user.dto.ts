import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @ApiProperty({ description: 'User email', required: true })
  email: string;

  @IsNotEmpty()
  @ApiProperty({ description: 'User password', required: true })
  password: string;
}
