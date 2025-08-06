import { NestFactory } from '@nestjs/core';
import { SocialServiceModule } from './social-service.module';

async function bootstrap() {
  const app = await NestFactory.create(SocialServiceModule);
  await app.listen(process.env.port ?? 3000);
}
bootstrap();
