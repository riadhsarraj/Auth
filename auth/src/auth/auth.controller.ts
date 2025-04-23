import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Put, Req, UnauthorizedException, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { AuthGuard } from 'src/guards/auth.guard';
import { ForgotPasswordDto } from './dto/forget-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { SendOTPDto } from './dto/send-otp.dto';
import { VerifyOTPDto } from './dto/verify-otp.dto';
import { SMSService } from 'src/service/sms.service';
import { GoogleAuthDto } from './dto/google-auth.dto';
import { AppleAuthDto } from './dto/apple-auth.dto';
import { AuthGuard as PassportAuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { OAuth2Client } from 'google-auth-library';

@Controller('auth')
export class AuthController {
  private googleClient: OAuth2Client;

  constructor(
    private readonly authService: AuthService,
    private readonly smsService: SMSService,
  ) {
    this.googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  }

  @Post('signup')
  async signup(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData);
  }

  @Post('login')
  async login(@Body() loginData: LoginDto) {
    return this.authService.login(loginData);
  }

  @Post('refresh')
  async refreshToken(@Body('refreshToken') refreshToken: string) {
    return this.authService.refreshToken(refreshToken);
  }
  @UseGuards (AuthGuard)
  @Put ('change-password')
  async changePassword(@Body() changePasswordDto: ChangePasswordDto, @Req() req,) {
    return this.authService.changePassword(req.userId, changePasswordDto.oldPassword, changePasswordDto.newPassword);
  }
  @Post ('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }
  @Put ('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto.newPassword, resetPasswordDto.resetToken);
  }

  @Post('send-otp')
  async sendOTP(@Body() sendOTPDto: SendOTPDto) {
    await this.smsService.sendOTP(sendOTPDto.phoneNumber);
    return { message: 'OTP sent successfully' };
  }

  @Post('verify-otp')
  async verifyOTP(@Body() verifyOTPDto: VerifyOTPDto) {
    const isValid = await this.smsService.verifyOTP(verifyOTPDto.phoneNumber, verifyOTPDto.otp);
    if (!isValid) {
      throw new UnauthorizedException('Invalid OTP');
    }
    return { message: 'OTP verified successfully' };
  }

  @Get('google')
  @UseGuards(PassportAuthGuard('google'))
  async googleAuth() {
    // This will redirect to Google's OAuth page
  }

  @Get('google/callback')
  @UseGuards(PassportAuthGuard('google'))
  async googleAuthCallback(@Req() req, @Res() res: Response) {
    const result = await this.authService.handleGoogleLogin(req.user);
    // Redirect to frontend with tokens
    res.redirect(`http://localhost:3000/auth/callback?accessToken=${result.accessToken}&refreshToken=${result.refreshToken}`);
  }

  @Get('apple')
  @UseGuards(PassportAuthGuard('apple'))
  async appleAuth() {
    // This will redirect to Apple's Sign In page
  }

  @Post('apple/callback')
  @UseGuards(PassportAuthGuard('apple'))
  async appleAuthCallback(@Req() req, @Res() res: Response) {
    const result = await this.authService.handleAppleLogin(req.user);
    // Redirect to frontend with tokens
    res.redirect(`http://localhost:3000/auth/callback?accessToken=${result.accessToken}&refreshToken=${result.refreshToken}`);
  }

  @Post('google/verify')
  async verifyGoogleToken(@Body('token') token: string) {
    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });

      const payload = ticket.getPayload();
      if (!payload) {
        throw new UnauthorizedException('Invalid token');
      }

      const user = {
        email: payload.email,
        firstName: payload.given_name,
        lastName: payload.family_name,
        picture: payload.picture,
        provider: 'google',
        accessToken: token,
      };

      return this.authService.handleGoogleLogin(user);
    } catch (error) {
      throw new UnauthorizedException('Invalid Google token');
    }
  }
}

