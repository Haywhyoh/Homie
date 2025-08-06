import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
  Index
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { State } from './state.entity';
import { Neighborhood } from './neighborhood.entity';

@Entity('local_government_areas')
@Index(['stateId'])
export class LocalGovernmentArea {
  @ApiProperty({ description: 'Unique identifier for the LGA' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ description: 'State ID this LGA belongs to' })
  @Column({ name: 'state_id' })
  stateId: number;

  @ApiProperty({ description: 'LGA name', example: 'Ikeja' })
  @Column({ length: 100 })
  name: string;

  @ApiProperty({ description: 'LGA creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  // Relations
  @ManyToOne(() => State, state => state.localGovernmentAreas)
  @JoinColumn({ name: 'state_id' })
  state: State;

  @OneToMany(() => Neighborhood, neighborhood => neighborhood.lga)
  neighborhoods: Neighborhood[];
}