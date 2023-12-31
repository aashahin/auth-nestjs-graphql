import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';
import { UserService } from './user.service';
import { UseGuards } from '@nestjs/common';
import { GraphqlAuthGuard } from '../auth/guard/graphql-auth.guard';
import { User } from './user.types';
import { FileUpload, GraphQLUpload } from 'graphql-upload-ts';
import {Request} from 'express';
import { join } from 'path';
import { createWriteStream } from 'fs';

@Resolver()
export class UserResolver {
  constructor(
    private readonly userService: UserService
  ) {}

  @UseGuards(GraphqlAuthGuard)
  @Mutation(()=> User)
  async updateProfile(
    @Args('fullname') fullname: string,
    @Args('file', {
      type: ()=> GraphQLUpload,
      nullable: true
    }) file: FileUpload,
    @Context() context: {req: Request}
  ){
    const imageUrl = file ? await this.storeImageAndGetUrl(file) : null;
    const userId = context.req.user.sub;

    return this.userService.updateProfile(
      userId,
      fullname,
      imageUrl,
    )
  }

  private async storeImageAndGetUrl(file: FileUpload) {
    const { createReadStream, filename } = file;
    const uniqueFilename = new Date().toISOString() + filename;
    const imagePath = join(process.cwd(), 'public', uniqueFilename);
    const imageUrl = `${process.env.APP_URL}/${uniqueFilename}`;
    const readStream = createReadStream();

    readStream.pipe(createWriteStream(imagePath));
    return imageUrl;
  }
}
