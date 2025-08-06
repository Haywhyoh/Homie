import { Injectable } from '@nestjs/common';

@Injectable()
export class MarketplaceServiceService {
  getHello(): string {
    return 'Hello World!';
  }
}
