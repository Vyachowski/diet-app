import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { MenuModule } from './menu/menu.module';
import { Menu } from './menu/entities/menu.entity';
import { MenuService } from './menu/menu.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './user/user.module';
import { User } from './user/entities/user.entity';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRoot({
      type: 'mongodb',
      url: `${process.env.MONGODB_URL}${process.env.MONGODB_NAME}`,
      authSource: 'admin',
      entities: [Menu, User],
    }),
    MenuModule,
    AuthModule,
    UsersModule,
  ],
  controllers: [AppController],
  providers: [AppService, MenuService],
})
export class AppModule {}
