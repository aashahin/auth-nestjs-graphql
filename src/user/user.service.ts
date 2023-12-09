import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService
  ) {}

  async updateProfile(
    userId: number,
    fullname: string,
    avatarUrl: string
  ) {
    const data = !avatarUrl ? {fullname} : {fullname, avatarUrl};

    return this.prisma.user.update({
      where: { id: userId },
      data
    })
  }
}
