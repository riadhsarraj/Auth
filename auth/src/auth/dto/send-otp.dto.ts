import { IsNotEmpty, IsPhoneNumber } from 'class-validator';

export class SendOTPDto {
  @IsPhoneNumber()
  @IsNotEmpty()
  phoneNumber: string;
} 