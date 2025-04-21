import { Controller, Get, Req } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthGuard } from './guards/auth.guard';
import { UseGuards } from '@nestjs/common';
@UseGuards(AuthGuard)
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
someProtectedRoute(@Req() req) {
  return { message: 'accessed resource', userId: req.userId };
}
}
