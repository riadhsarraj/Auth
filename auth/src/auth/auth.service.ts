import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schemas';
import { Model } from 'mongoose';
import { SignupDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
  constructor (
    @InjectModel(User.name) private userModel: Model<User>, 
  private jwtService: JwtService, ){}
  async signup(signupData: SignupDto) {
    const {name, email, password} = signupData;
    const emailInUse = await this.userModel.findOne({email});
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
  const {email, password} = credentials;
  const user = await this.userModel.findOne({email});
  if (!user) {
    throw new UnauthorizedException('Invalid credentials');
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    throw new UnauthorizedException('Invalid credentials');
  }
  return this.generateToken(user._id);
}
async generateToken(userId) {
  const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
  return {
    accessToken,
  }
}
}

