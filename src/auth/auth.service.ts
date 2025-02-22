import { ConflictException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<User | null> {
    try {
      const user = await this.usersService.findOneByEmail(email);
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
    const existingUser = await this.usersService.findOneByEmail(email);

    if (existingUser) {
      throw new ConflictException('Email already registered.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await this.usersService.create({
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
}
