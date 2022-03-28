import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BoardsModule } from './boards/boards.module';
import { TypeORMConfig } from './configs/typeorm.config';

@Module({
  imports: [BoardsModule, TypeOrmModule.forRoot(TypeORMConfig)],
})
export class AppModule {}
