import { IsString } from "class-validator";

export class RefreshTokenDto {
    static refreshToken(refreshToken: any) {
      throw new Error('Method not implemented.');
    }
    @IsString()
    refreshToken: string;
}
