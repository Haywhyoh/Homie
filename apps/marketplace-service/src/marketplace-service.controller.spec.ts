import { Test, TestingModule } from '@nestjs/testing';
import { MarketplaceServiceController } from './marketplace-service.controller';
import { MarketplaceServiceService } from './marketplace-service.service';

describe('MarketplaceServiceController', () => {
  let marketplaceServiceController: MarketplaceServiceController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [MarketplaceServiceController],
      providers: [MarketplaceServiceService],
    }).compile();

    marketplaceServiceController = app.get<MarketplaceServiceController>(MarketplaceServiceController);
  });

  describe('root', () => {
    it('should return "Hello World!"', () => {
      expect(marketplaceServiceController.getHello()).toBe('Hello World!');
    });
  });
});
