import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn,
  OneToMany,
  Index
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { LocalGovernmentArea } from './local-government-area.entity';

@Entity('states')
@Index(['code'], { unique: true })
export class State {
  @ApiProperty({ description: 'Unique identifier for the state' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ description: 'State name', example: 'Lagos' })
  @Column({ length: 100 })
  name: string;

  @ApiProperty({ description: 'State code', example: 'LG' })
  @Column({ length: 10, unique: true })
  code: string;

  @ApiProperty({ description: 'State creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  // Relations
  @OneToMany(() => LocalGovernmentArea, lga => lga.state)
  localGovernmentAreas: LocalGovernmentArea[];
}