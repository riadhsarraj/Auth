import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  private transporter=nodemailer.Transporter;
  
  constructor() {
    this.transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        auth: {
            user: process.env.EMAIL, 
            pass: process.env.EMAIL_PASSWORD
        }
    });
  }
  async sendMail(to: string, token: string) {
    const resetLink = `https://localhost:3000/auth/reset-password?token=${token}`;
    const mailOptions = {
      from: 'Auth-backend service',
      to: to,
      subject: 'Password reset',
      html: `<p>Hello, your password reset token is</p><p><a href="${resetLink}">Reset password</a></p>`,
    };
    await this.transporter.sendMail(mailOptions);
  }
  
}
