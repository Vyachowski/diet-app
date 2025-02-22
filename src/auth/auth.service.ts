import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { User } from 'src/user/entities/user.entity';
import { CONSTANTS } from 'src/shared';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<User | null> {
    try {
      const user = await this.userService.findOneByEmail(email);
      const isPasswordMatch = await bcrypt.compare(pass, user?.password);

      return user && isPasswordMatch ? user : null;
    } catch (e) {
      console.error(e?.message);
      return null;
    }
  }

  async login(user: User) {
    const payload = { email: user.email, sub: user._id.toString() };

    return {
      accessToken: this.jwtService.sign(payload, { expiresIn: '15m' }),
      refreshToken: this.jwtService.sign(payload, {
        expiresIn: '7d',
      }),
    };
  }

  async signUp(email: string, password: string) {
    const existingUser = await this.userService.findOneByEmail(email);

    if (existingUser) {
      throw new ConflictException('Email already registered.');
    }

    const hashedPassword = await bcrypt.hash(password, CONSTANTS.PASSWORD_SALT_ROUNDS_AMOUNT);
    const newUser = await this.userService.create({
      email,
      password: hashedPassword,
    });

    const payload = { username: newUser.email, sub: newUser._id.toString() };

    return {
      accessToken: this.jwtService.sign(payload, { expiresIn: '15m' }),
      refreshToken: this.jwtService.sign(payload, {
        expiresIn: '7d',
      }),
      user: newUser,
    };
  }

  verifyJwtToken(token: string) {
    try {
      const decoded = this.jwtService.verify(token);
      return decoded;
    } catch (e) {
      console.error(e);
      return null;
    }
  }

  async refreshToken(oldRefreshToken: string) {
    const payload = await this.verifyJwtToken(oldRefreshToken);

    if (!payload) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.userService.findOne(payload.userId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const accessToken =  this.jwtService.sign(user, { expiresIn: '15m' });
    const newRefreshToken = this.jwtService.sign(user, { expiresIn: '15m' });

    return { accessToken, newRefreshToken };
  }  
}
