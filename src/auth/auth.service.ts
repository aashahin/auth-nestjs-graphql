import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma.service';
import { Request, Response } from 'express';
import { User } from '../user/user.types';
import { LoginDto, RegisterDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  async refreshToken(req: Request, res: Response) {
    const refreshToken = req.cookies['refresh_token'];

    if (!refreshToken) {
      throw new UnauthorizedException('$[Refresh_Token] not found');
    }

    let payload: any;

    try {
      payload = this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get<string>('SECRET_REFRESH_TOKEN'),
      });
    } catch (e) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const userExist = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!userExist) {
      throw new BadRequestException('User no longer exist');
    }

    const accessToken = this.jwtService.sign(
      {
        ...payload,
        exp: Math.floor(Date.now() / 1000) + 15 * 60,
      },
      {
        secret: this.configService.get<string>('SECRET_ACCESS_TOKEN'),
      },
    );

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get<string>('NODE_ENV') === 'production',
    });

    return accessToken;
  }

  private async issueTokens(user: User, res: Response) {
    const payload = {
      username: user.fullname,
      sub: user.id,
    };

    const accessToken = this.jwtService.sign(
      {
        ...payload,
      },
      {
        secret: this.configService.get<string>('SECRET_ACCESS_TOKEN'),
        expiresIn: '150sec',
      },
    );
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('SECRET_REFRESH_TOKEN'),
      expiresIn: '7d',
    });

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get<string>('NODE_ENV') === 'production',
    });
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: this.configService.get<string>('NODE_ENV') === 'production',
    });

    return { user };
  }

  async validateUser(loginDto: LoginDto){
    const user = await this.prisma.user.findUnique({
      where: {email: loginDto.email}
    });

    if(user && (await bcrypt.compare(loginDto.password, user.password))) {
      return user;
    }
    return null;
  }

  async register(res: Response,registerDto: RegisterDto) {
      const exist = await this.prisma.user.findUnique({
        where: {email: registerDto.email}
      })

    if(exist) {
      throw new BadRequestException('Email already exist');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    const user = await this.prisma.user.create({
      data: {
        fullname: registerDto.fullname,
        email: registerDto.email,
        password: hashedPassword,
      }
    });

    return this.issueTokens(user, res);
  }

  async login(res: Response, loginDto: LoginDto) {
    const user = await this.validateUser(loginDto);

    if(!user) {
      throw new BadRequestException('Invalid credentials');
    }

    return this.issueTokens(user, res);
  }

  async logout(res: Response) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return 'Logout successfully';
  }
}
