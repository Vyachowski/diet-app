import ms from 'ms';
import password from 'secure-random-password';
import * as bcrypt from 'bcrypt';
import {
  Controller,
  Get,
  Post,
  Body,
  Render,
  UseGuards,
  Res,
  Req,
  UnauthorizedException,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Response } from 'express';
import { UserService } from 'src/user/user.service';
import { ResetPasswordDTO } from './dto/reset-password.dto';
import { EmailService } from 'src/email/email.service';
import { CONSTANTS } from 'src/shared';

@Controller()
export class AuthPageController {
  @Get('/login')
  @Render('login')
  renderLoginPage(@Req() req) {
    return {
      error: req.flash('error')[0] || '',
      success: req.flash('success')[0] || '',
      email: req.flash('email')[0] || '',
      password: req.flash('password')[0] || '',
    };
  }

  @Get('/sign-up')
  @Render('sign-up')
  renderSignInPage(@Req() req) {
    return {
      error: req.flash('error')[0] || '',
      email: req.flash('email')[0] || '',
      password: req.flash('password')[0] || '',
    };
  }

  @Get('/reset-password')
  @Render('reset-password')
  renderRestorePasswordPage(@Req() req) {
    return {
      error: req.flash('error')[0] || '',
      email: req.flash('email')[0] || '',
    };
  }
}

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService, private userService: UserService, private emailService: EmailService) {}

  @UseGuards(JwtAuthGuard)
  @Get('/me')
  getProfile(@Req() req) {
    return req.user;
  }

  @Post('/sign-up')
  async signUp(
    @Body() registerDto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req,
  ) {
    const { email, password, passwordConfirmation } = registerDto;
    const existingUser = await this.userService.findOneByEmail(email);
    const isPasswordInvalid = password !== passwordConfirmation;

    if (isPasswordInvalid) {
      req.flash('error', 'Password and password confirmation are not equal.');
      req.flash('email', req.body.email);
      req.flash('password', req.body.password);

      return res.redirect('/sign-up');
    }

    if (existingUser) {
      req.flash('error', 'The user already exists.');
      req.flash('email', req.body.email);
      req.flash('password', req.body.password);

      return res.redirect('/sign-up');
    }

    try {
      const { accessToken, refreshToken } = await this.authService.signUp(
        email,
        password,
      );

      res.cookie('access_token', accessToken, {
        httpOnly: true,
        maxAge: ms('15 minutes'),
      });
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        maxAge: ms('7 days'),
      });

      res.redirect('/');
    } catch (e) {
      console.error(e?.message);
      console.log(e?.stack);
      res.redirect('/sign-up');
    }
  }

  @UseGuards(LocalAuthGuard)
  @Post('/login')
  async login(@Req() req, @Res() res) {
    const { accessToken, refreshToken } = await this.authService.login(
      req.user,
    );

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      maxAge: ms('15 minutes'),
    });
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      maxAge: ms('7 days'),
    });

    res.redirect('/');
  }

  @UseGuards(JwtAuthGuard)
  @Post('/logout')
  async logout(@Res() res) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    res.redirect('/login');
  }

  @Post('/refresh-token')
  async refreshToken(@Req() req, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies['refresh_token'];
  
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is missing');
    }
  
    try {
      const { accessToken, newRefreshToken } = await this.authService.refreshToken(refreshToken);
  
      res.cookie('access_token', accessToken, {
        httpOnly: true,
        maxAge: ms('15 minutes'),
      });
      res.cookie('refresh_token', newRefreshToken, {
        httpOnly: true,
        maxAge: ms('7 days'),
      });
  
      return { accessToken };
    } catch (e) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }
  

  @Post('/reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDTO, @Req() req, @Res() res) {
    const { email } = resetPasswordDto;
  
    try {
      const user = await this.userService.findOneByEmail(email);
      
      if (!user) {
        req.flash('error', "User with this email doesn't exist");
        req.flash('email', req.body.email);

        return res.redirect('/reset-password');
      }

      const newPassword = password.randomPassword();
      const newHashedPassword = await bcrypt.hash(newPassword, CONSTANTS.PASSWORD_SALT_ROUNDS_AMOUNT);

      this.emailService.sendEmail(user.email, 'New password created', `Your new password is: ${newPassword}`);
      this.userService.changePassword(user._id, newHashedPassword);

      req.flash('success', "New password was sent to your email box.");

      return res.redirect('/login');
    } catch(e) {
      req.flash('error', 'Something went wrong. Please, try again');
      req.flash('email', req.body.email);

      return res.redirect('/reset-password');
    }
  }
}
