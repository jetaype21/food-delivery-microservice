import { Field, InputType } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

@InputType()
export class RegisterDto {
  @Field()
  @IsNotEmpty({ message: 'name Must not be empty' })
  @IsString({ message: 'name Must be a string' })
  name: string;

  @Field()
  @IsNotEmpty({ message: 'password Must not be empty' })
  @MinLength(8, { message: 'Min length 8 - password' })
  password: string;

  @Field()
  @IsNotEmpty({ message: 'email Must not be empty' })
  @IsEmail({}, { message: 'email Must be a string' })
  email: string;

  @Field()
  @IsNotEmpty({ message: 'phone number Must not be empty' })
  phone_number: number;
}

@InputType()
export class ActivationDto {
  @Field()
  @IsNotEmpty({ message: 'Activation token is required' })
  activationToken: string;

  @Field()
  @IsNotEmpty({ message: 'Activation code is required' })
  activationCode: string;
}

@InputType()
export class LoginDto {
  @Field()
  @IsNotEmpty({ message: 'Must not be empty' })
  @IsEmail({}, { message: 'Must be a string' })
  email: string;

  @Field()
  @IsNotEmpty({ message: 'Must not be empty' })
  password: string;
}
