import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SeederService } from './seeder.service';
import { State, LocalGovernmentArea, PostCategory } from '../entities';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      State,
      LocalGovernmentArea,
      PostCategory,
    ]),
  ],
  providers: [SeederService],
  exports: [SeederService],
})
export class SeederModule {}