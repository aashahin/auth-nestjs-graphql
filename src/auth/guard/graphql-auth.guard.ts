import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class GraphqlAuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService
  ) {}

  private extractToken(req: Request): string | undefined {
    return req?.cookies?.access_token;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const gqlContext = context.getArgByIndex(2);
    const req: Request = gqlContext.req;
    const token = this.extractToken(req);

    if(!token) {
      throw new UnauthorizedException('No token provided');
    }

    try{
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });
      console.log(payload);
      req['user'] = payload;
    } catch (e) {
      throw new UnauthorizedException('Not authorized');
    }

    return true;
  }
}