import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schemas';
import { Model } from 'mongoose';
import { SignupDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { ResetToken } from './schemas/reset-token.schema';
import { MailService } from 'src/service/mail.service';
@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
      @InjectModel(RefreshToken.name)
      private refreshTokenModel: Model<RefreshToken>,
      @InjectModel(ResetToken.name)
      private resetTokenModel: Model<ResetToken>,
      private jwtService: JwtService,
      private mailService: MailService,
  ) {}
  async signup(signupData: SignupDto) {
    const { name, email, password } = signupData;
    const emailInUse = await this.userModel.findOne({ email });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await this.userModel.create({
      name,
      email,
      password: hashedPassword,
    });
  }
  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const token = await this.generateToken(user._id);
    return {
      ...token,
      userId: user._id,
    };
  }
  async refreshToken(refreshToken: String) {
    const token = await this.refreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gt: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return this.generateToken(token.userId);
  }
  async generateToken(userId) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);
    return {
      accessToken,
      refreshToken,
    };
  }
  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid old password');
    }
    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = newHashedPassword;
    await user.save();
    
  }
  async forgotPassword(email: string) {
    const user = await this.userModel.findOne({ email });
   
    if (user) {
      const expiryDate = new Date();
      expiryDate.setHours(expiryDate.getHours() + 1);
     const resetToken = nanoid(64);
     await this.resetTokenModel.create({
      token: resetToken,
      userId: user._id,
      expiryDate,
     });
     this.mailService.sendMail(email, resetToken);
    }
    
  }

  async storeRefreshToken(token: string, userId) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);
    await this.refreshTokenModel.updateOne(
      {
        userId,
      },
      {
        $set: {
          token,
          expiryDate,
        },
      },
      { upsert: true },
    );
  }

  async resetPassword(newPassword: string, resetToken: string) {
    const token = await this.resetTokenModel.findOneAndDelete({ token: resetToken  ,expiryDate: {$gt: new Date()}});
    if (!token) {
      throw new UnauthorizedException('Invalid Link');
    }
    const user = await this.userModel.findById(token.userId);
    if (!user) {
      throw new InternalServerErrorException();
    }
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    
    
  }
}
