import {
  Controller,
  Get,
  Render,
  Request,
  Response,
  UseGuards,
} from '@nestjs/common';
import { groceryList } from './common/basic-menu';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { UserService } from './user/user.service';

@Controller()
export class AppController {
  constructor(private userService: UserService) {}
  @Get()
  @UseGuards(JwtAuthGuard)
  @Render('index')
  async root(@Request() req, @Response() res) {
    if (!req.user) {
      res.redirect('/login');
    }

    const menu = await this.userService.getUserMenu(req.user.id);

    return {
      email: req.user.email,
      menu: menu,
      groceryList,
    };
  }
}
