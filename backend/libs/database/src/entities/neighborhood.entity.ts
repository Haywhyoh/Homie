import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
  Index
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { LocalGovernmentArea } from './local-government-area.entity';
import { User } from './user.entity';
import { UserNeighborhood } from './user-neighborhood.entity';
import { Post } from './post.entity';

@Entity('neighborhoods')
@Index(['lgaId'])
@Index(['centerLatitude', 'centerLongitude'])
export class Neighborhood {
  @ApiProperty({ description: 'Unique identifier for the neighborhood' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'Neighborhood name', example: 'Victoria Island' })
  @Column({ length: 200 })
  name: string;

  @ApiProperty({ description: 'Neighborhood description', required: false })
  @Column({ type: 'text', nullable: true })
  description?: string;

  @ApiProperty({ description: 'Local Government Area ID' })
  @Column({ name: 'lga_id' })
  lgaId: number;

  @ApiProperty({ description: 'GeoJSON boundary coordinates', required: false })
  @Column({ name: 'boundary_coordinates', type: 'jsonb', nullable: true })
  boundaryCoordinates?: any;

  @ApiProperty({ description: 'Center latitude', example: 6.4281 })
  @Column({ name: 'center_latitude', type: 'decimal', precision: 10, scale: 8 })
  centerLatitude: number;

  @ApiProperty({ description: 'Center longitude', example: 3.4219 })
  @Column({ name: 'center_longitude', type: 'decimal', precision: 11, scale: 8 })
  centerLongitude: number;

  @ApiProperty({ description: 'Radius in meters', example: 1000 })
  @Column({ name: 'radius_meters', default: 1000 })
  radiusMeters: number;

  @ApiProperty({ description: 'Whether neighborhood is verified' })
  @Column({ name: 'is_verified', default: false })
  isVerified: boolean;

  @ApiProperty({ description: 'User ID who created this neighborhood' })
  @Column({ name: 'created_by' })
  createdBy: string;

  @ApiProperty({ description: 'Neighborhood creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  // Relations
  @ManyToOne(() => LocalGovernmentArea, lga => lga.neighborhoods)
  @JoinColumn({ name: 'lga_id' })
  lga: LocalGovernmentArea;

  @ManyToOne(() => User)
  @JoinColumn({ name: 'created_by' })
  creator: User;

  @OneToMany(() => UserNeighborhood, userNeighborhood => userNeighborhood.neighborhood)
  userNeighborhoods: UserNeighborhood[];

  @OneToMany(() => Post, post => post.neighborhood)
  posts: Post[];

  // Helper methods
  getDistanceFromPoint(lat: number, lng: number): number {
    const R = 6371e3; // Earth's radius in meters
    const φ1 = (this.centerLatitude * Math.PI) / 180;
    const φ2 = (lat * Math.PI) / 180;
    const Δφ = ((lat - this.centerLatitude) * Math.PI) / 180;
    const Δλ = ((lng - this.centerLongitude) * Math.PI) / 180;

    const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
      Math.cos(φ1) * Math.cos(φ2) *
      Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
  }

  isPointWithinRadius(lat: number, lng: number): boolean {
    return this.getDistanceFromPoint(lat, lng) <= this.radiusMeters;
  }
}