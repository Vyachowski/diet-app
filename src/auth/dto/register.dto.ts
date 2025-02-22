import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail({}, { message: 'Invalid email format'})
  @IsNotEmpty()
  @ApiProperty({
    description: 'User email for registration',
    required: true,
  })
  email: string;

  @IsNotEmpty()
  @MinLength(6, { message: 'Password must be at least 6 characters long' })
  @ApiProperty({
    description: 'User password for registration',
    required: true,
  })
  password: string;

  @IsNotEmpty()
  @ApiProperty({
    description: 'User password confirmation for registration',
    required: true,
  })
  passwordConfirmation: string;
}
