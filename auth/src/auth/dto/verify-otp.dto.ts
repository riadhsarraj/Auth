import { IsNotEmpty, IsString, Length } from 'class-validator';

export class VerifyOTPDto {
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;

  @IsString()
  @IsNotEmpty()
  phoneNumber: string;
} 