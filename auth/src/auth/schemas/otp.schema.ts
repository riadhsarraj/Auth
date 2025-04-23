import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class OTP extends Document {
  @Prop({ required: true })
  phoneNumber: string;

  @Prop({ required: true })
  otp: string;

  @Prop({ required: true })
  expiryDate: Date;
}

export const OTPSchema = SchemaFactory.createForClass(OTP); 