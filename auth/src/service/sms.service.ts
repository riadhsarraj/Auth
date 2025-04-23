import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as twilio from 'twilio';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { OTP } from '../auth/schemas/otp.schema';

@Injectable()
export class SMSService {
  private twilioClient: twilio.Twilio;
  private readonly logger = new Logger(SMSService.name);

  constructor(
    private configService: ConfigService,
    @InjectModel(OTP.name) private otpModel: Model<OTP>,
  ) {
    const accountSid = this.configService.get('TWILIO_ACCOUNT_SID');
    const authToken = this.configService.get('TWILIO_AUTH_TOKEN');
    
    if (!accountSid || !authToken) {
      this.logger.error('Twilio credentials not found in environment variables');
      throw new Error('Twilio credentials not configured');
    }

    this.twilioClient = twilio(accountSid, authToken);
    this.logger.log('Twilio client initialized successfully');
  }

  async sendOTP(phoneNumber: string): Promise<void> {
    try {
      this.logger.log(`Attempting to send OTP to ${phoneNumber}`);
      
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiryDate = new Date();
      expiryDate.setMinutes(expiryDate.getMinutes() + 5);

      await this.otpModel.create({
        phoneNumber,
        otp,
        expiryDate,
      });

      this.logger.log(`OTP ${otp} created for ${phoneNumber}`);

      const message = await this.twilioClient.messages.create({
        body: `Your OTP code is: ${otp}. Valid for 5 minutes.`,
        to: phoneNumber,
        from: this.configService.get('TWILIO_PHONE_NUMBER'),
      });

      this.logger.log(`SMS sent successfully. Message SID: ${message.sid}`);
    } catch (error) {
      this.logger.error(`Error sending OTP: ${error.message}`, error.stack);
      throw error;
    }
  }

  async verifyOTP(phoneNumber: string, otp: string): Promise<boolean> {
    try {
      this.logger.log(`Verifying OTP for ${phoneNumber}`);
      
      const otpRecord = await this.otpModel.findOne({
        phoneNumber,
        otp,
        expiryDate: { $gt: new Date() },
      });

      if (!otpRecord) {
        this.logger.warn(`Invalid OTP attempt for ${phoneNumber}`);
        return false;
      }

      await this.otpModel.deleteOne({ _id: otpRecord._id });
      this.logger.log(`OTP verified successfully for ${phoneNumber}`);
      return true;
    } catch (error) {
      this.logger.error(`Error verifying OTP: ${error.message}`, error.stack);
      throw error;
    }
  }
} 