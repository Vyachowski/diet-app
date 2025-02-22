import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class ResetPasswordDTO {
  @IsEmail({}, { message: 'Invalid email format'})
  @IsNotEmpty()
  @ApiProperty({
    description: 'User email for passowrd recovery',
    required: true,
  })
  email: string;
}
