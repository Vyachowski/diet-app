import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { MenuService } from 'src/menu/menu.service';

@Module({
  controllers: [UserController],
  providers: [UserService, MenuService],
  exports: [UserService],
})
export class UsersModule {}
