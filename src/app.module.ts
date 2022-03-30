import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BoardsModule } from './boards/boards.module';
import { TypeORMConfig } from './configs/typeorm.config';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [BoardsModule, TypeOrmModule.forRoot(TypeORMConfig), AuthModule],
})
export class AppModule {}
