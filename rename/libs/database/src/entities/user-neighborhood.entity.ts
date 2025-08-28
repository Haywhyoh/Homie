import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  Unique
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { User } from './user.entity';
import { Neighborhood } from './neighborhood.entity';

@Entity('user_neighborhoods')
@Index(['userId'])
@Index(['neighborhoodId'])
@Unique(['userId', 'neighborhoodId'])
export class UserNeighborhood {
  @ApiProperty({ description: 'Unique identifier for the user-neighborhood relationship' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'User ID' })
  @Column({ name: 'user_id' })
  userId: string;

  @ApiProperty({ description: 'Neighborhood ID' })
  @Column({ name: 'neighborhood_id' })
  neighborhoodId: string;

  @ApiProperty({ 
    description: 'Type of relationship', 
    enum: ['resident', 'worker', 'visitor'],
    example: 'resident'
  })
  @Column({ name: 'relationship_type', length: 20 })
  relationshipType: string;

  @ApiProperty({ 
    description: 'How the relationship was verified', 
    enum: ['gps', 'referral', 'manual'],
    example: 'gps'
  })
  @Column({ name: 'verification_method', length: 50 })
  verificationMethod: string;

  @ApiProperty({ description: 'User ID who verified this relationship', required: false })
  @Column({ name: 'verified_by', nullable: true })
  verifiedBy?: string;

  @ApiProperty({ description: 'Whether this is the user\'s primary neighborhood' })
  @Column({ name: 'is_primary', default: false })
  isPrimary: boolean;

  @ApiProperty({ description: 'When user joined this neighborhood' })
  @CreateDateColumn({ name: 'joined_at' })
  joinedAt: Date;

  // Relations
  @ManyToOne(() => User, user => user.userNeighborhoods, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ManyToOne(() => Neighborhood, neighborhood => neighborhood.userNeighborhoods, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'neighborhood_id' })
  neighborhood: Neighborhood;

  @ManyToOne(() => User, { nullable: true })
  @JoinColumn({ name: 'verified_by' })
  verifier?: User;
}