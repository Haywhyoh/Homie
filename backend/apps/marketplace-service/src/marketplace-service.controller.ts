import { Controller, Get } from '@nestjs/common';
import { MarketplaceServiceService } from './marketplace-service.service';

@Controller()
export class MarketplaceServiceController {
  constructor(private readonly marketplaceServiceService: MarketplaceServiceService) {}

  @Get()
  getHello(): string {
    return this.marketplaceServiceService.getHello();
  }
}
