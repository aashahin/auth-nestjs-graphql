import { Field, InputType } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

@InputType()
export class RegisterDto {
  @Field()
  @IsNotEmpty({ message: 'Please enter your full name.' })
  @IsString({ message: 'Please enter a string.' })
  fullname: string;

  @Field()
  @IsNotEmpty({ message: 'Please enter your email.' })
  @IsEmail({}, { message: 'Please enter a valid email.' })
  email: string;

  @Field()
  @IsNotEmpty({ message: 'Please enter your password.' })
  @MinLength(8, { message: 'Password must be at least 8 characters.' })
  @IsString({ message: 'Please enter a string.' })
  password: string;

  @Field()
  @IsNotEmpty({ message: 'Please confirm your password.' })
  @MinLength(8, { message: 'Password must be at least 8 characters.' })
  @IsString({ message: 'Please enter a string.' })
  confirmPassword: string;
}

@InputType()
export class LoginDto {
  @Field()
  @IsNotEmpty({ message: 'Please enter your email.' })
  @IsEmail({}, { message: 'Please enter a valid email.' })
  email: string;

  @Field()
  @IsNotEmpty({ message: 'Please enter your password.' })
  @IsString({ message: 'Please enter a string.' })
  password: string;
}