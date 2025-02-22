import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsEmail()
  @IsNotEmpty()
  @ApiProperty({ description: 'User email for login', required: true })
  email: string;

  @IsNotEmpty()
  @ApiProperty({ description: 'User password for login', required: true })
  password: string;
}
