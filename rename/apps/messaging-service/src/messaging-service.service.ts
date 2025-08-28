import { Injectable } from '@nestjs/common';

@Injectable()
export class MessagingServiceService {
  getHello(): string {
    return 'Hello World!';
  }
}
