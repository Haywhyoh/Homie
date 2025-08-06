import { Module } from '@nestjs/common';
import { MarketplaceServiceController } from './marketplace-service.controller';
import { MarketplaceServiceService } from './marketplace-service.service';

@Module({
  imports: [],
  controllers: [MarketplaceServiceController],
  providers: [MarketplaceServiceService],
})
export class MarketplaceServiceModule {}
