import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User, UserSchema } from './schemas/user.schemas';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { RefreshToken, RefreshTokenSchema } from './schemas/refresh-token.schema';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ResetToken, ResetTokenSchema } from './schemas/reset-token.schema';
import { MailService } from 'src/service/mail.service';
import { SMSService } from 'src/service/sms.service';
import { OTP, OTPSchema } from './schemas/otp.schema';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './strategies/google.strategy';
import { AppleStrategy } from './strategies/apple.strategy';

@Module({
  imports: [
    PassportModule,
    MongooseModule.forFeature([
      {name: User.name, schema: UserSchema},
      {name: RefreshToken.name, schema: RefreshTokenSchema},
      {name: ResetToken.name, schema: ResetTokenSchema},
      {name: OTP.name, schema: OTPSchema},
    ]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '24h' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, MailService, SMSService, GoogleStrategy, AppleStrategy],
})
export class AuthModule {}
 