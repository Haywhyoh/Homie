import { NestFactory } from '@nestjs/core';
import { MarketplaceServiceModule } from './marketplace-service.module';

async function bootstrap() {
  const app = await NestFactory.create(MarketplaceServiceModule);
  await app.listen(process.env.port ?? 3000);
}
bootstrap();
