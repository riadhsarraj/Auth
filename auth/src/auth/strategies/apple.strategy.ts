import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-oauth2';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppleStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    const clientID = configService.get('APPLE_CLIENT_ID') || '';
    const callbackURL = configService.get('APPLE_CALLBACK_URL') || '';
    const teamId = configService.get('APPLE_TEAM_ID') || '';
    const keyId = configService.get('APPLE_KEY_ID') || '';
    const privateKey = configService.get('APPLE_PRIVATE_KEY') || '';
    
    super({
      authorizationURL: 'https://appleid.apple.com/auth/authorize',
      tokenURL: 'https://appleid.apple.com/auth/token',
      clientID,
      clientSecret: `${teamId}.${keyId}.${privateKey}`,
      callbackURL,
      scope: ['name', 'email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (err: any, user: any) => void,
  ): Promise<any> {
    try {
      const decodedToken = this.decodeToken(accessToken);
      const user = {
        email: decodedToken.email,
        firstName: decodedToken.name?.firstName,
        lastName: decodedToken.name?.lastName,
        provider: 'apple',
        accessToken,
      };
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  }

  private decodeToken(token: string): any {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(base64, 'base64').toString());
  }
} 