import { Controller, Get } from '@nestjs/common';
import { MessagingServiceService } from './messaging-service.service';

@Controller()
export class MessagingServiceController {
  constructor(private readonly messagingServiceService: MessagingServiceService) {}

  @Get()
  getHello(): string {
    return this.messagingServiceService.getHello();
  }
}
