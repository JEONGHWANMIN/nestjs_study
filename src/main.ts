import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as config from 'config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const serverConfig = config.get('server');
  const PORT = serverConfig.port;
  await app.listen(PORT);
  Logger.log(`Application runing on port ${PORT}`);
}
bootstrap();
