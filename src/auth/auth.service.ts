
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';

import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from "bcryptjs";


import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}


  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try{
      //todo
      // 1- encriptar contraseña
      

      const {password, ...userData} = createUserDto

      const newUser= new this.userModel({
        password:bcryptjs.hashSync(password,10),
        ...userData
      })

      
      // 2- guardar usuario

       await newUser.save()

       const {password:_, ...user} = newUser.toJSON()

       return user

      // 3- Generar el JWT json web token
        //ya quedó aparte en login()


    } catch(error){
      if (error.code===11000) {
        throw new BadRequestException(`${ createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException('Algo salió mal')
    }

  }

  async register(registerUser:RegisterUserDto): Promise<LoginResponse>{
    
    const {...userToReg} = registerUser
    // const userR= await this.create(userToReg)
    const userR= await this.create(registerUser)

    if (!userR) {
      throw new UnauthorizedException('No se pudo crear el usuario')
    }
    
    // Se agregó el _id en Entity User
    // const {email} =  userR
    // const user =await this.userModel.findOne({email})
    
    // if (!user){
    //   throw new UnauthorizedException('Credenciales no válidas - email')
    // }


    return {
      user: userR,
      token: this.getJWT({id:userR._id})
    }

  }


 async login(loginDto:LoginDto): Promise<LoginResponse>{

    const {email, password} =  loginDto
    
    

    const user =await this.userModel.findOne({email})
    
    if (!user){
      throw new UnauthorizedException('Credenciales no válidas - email')
    }
    
    if (!bcryptjs.compareSync(password,user.password)){
      throw new UnauthorizedException('Credenciales no válidas - password')
    }
    
    const {password:_, ...rest} = user.toJSON()
    
    return {
      user:rest,
      token: this.getJWT({id:user.id})
    }
    
  }



  findAll(): Promise<User[]> {
    return this.userModel.find()
  }

  async findUserById(userId: string){
    const user = await this.userModel.findById(userId)

    const {password, ...rest} = user.toJSON()
    return rest 

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

  getJWT(payload: JwtPayload ){
    const token = this.jwtService.sign(payload)
    return token

  }
}
