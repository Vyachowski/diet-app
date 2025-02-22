import {
  Controller,
  Get,
  Render,
  Request,
  Response,
  UseGuards,
} from '@nestjs/common';
import { MenuList } from './shared/data';
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
    const { groceryList } = MenuList.at(0);

    return {
      email: req.user.email,
      menu: menu,
      groceryList,
    };
  }
}
