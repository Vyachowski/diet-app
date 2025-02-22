import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  handleRequest(err, user, info, context: ExecutionContext) {
    const req = context?.switchToHttp()?.getRequest();
    const res = context?.switchToHttp()?.getResponse();

    if (err || !user) {
      req.flash('error', 'User is not logged in.');

      res.redirect('/login');

      throw new UnauthorizedException();
    }

    return user;
  }
}
