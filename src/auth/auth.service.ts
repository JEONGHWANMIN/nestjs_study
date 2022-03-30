import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthCredentialDto } from './dto/auth-credential.dto';
import { User } from './user.entity';
import { UserRepository } from './user.repository';
import * as bcrypt from 'bcryptjs';
@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserRepository)
    private userRepository: UserRepository,
  ) {}

  async signUp(authCredetialDto: AuthCredentialDto): Promise<void> {
    return await this.userRepository.createUser(authCredetialDto);
  }

  async signIn(authCredentialDto: AuthCredentialDto): Promise<string> {
    const { username, password } = authCredentialDto;
    const user = await this.userRepository.findOne({
      username,
    });
    if (user && (await bcrypt.compare(password, user.password))) {
      return user.username;
    } else {
      throw new UnauthorizedException('login falid');
    }
  }

  async deleteUser(id: number): Promise<void> {
    const found = await this.userRepository.delete(id);
    if (found.affected === 0) {
      throw new NotFoundException(`Not Found User By id ${id}`);
    }
  }
}
