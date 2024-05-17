import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';

import * as bcryptjs from "bcryptjs";

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto} from './dto';

import { User } from './entities/user.entity';

import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login.response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}


  async create(createUserDto: CreateUserDto): Promise<User> {
    //const newUser = new this.userModel( createUserDto );
    //return newUser.save();
    
    try {
      // 1.- Encriptar la contraseña
      // 2.- Guardar el usuario
      
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel( {
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      } );

      await newUser.save(); 
      const {password:_, ...user} = newUser.toJSON();

      return user; 

    } catch (error) {
      if( error.code === 11000 ){
        throw new BadRequestException(createUserDto.email+' already exists!');
      }
      throw new InternalServerErrorException('Something terrible happen!!');
      
    }
    

  }

  async register( registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    // const user = this.create
    const user = await this.create(registerUserDto);
    console.log({user});
    
   
    return {
      user: user,
      token: this.getJWT({ id: user._id })
    }
  }

  async login( loginDto: LoginDto ) :Promise<LoginResponse>  {
    /* Deberia regresar el usuario y JWT (Json Web Token) */
    //console.log({loginDto});

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email: email });
    if( !user ) {
      throw new UnauthorizedException('Not valid credentials - Email');
    }
    if( !bcryptjs.compareSync( password, user.password) ){
      throw new UnauthorizedException('Not valid credentials - Pass');
    }

    const { password:_, ...rest } = user.toJSON();
    
    
    
    return {
      user: rest,
      token: this.getJWT({ id: user.id })
    }

  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ) {
    const user = await this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();

    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWT( payload: JwtPayload ) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
