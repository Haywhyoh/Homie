import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  OneToMany
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Post } from './post.entity';

@Entity('post_categories')
export class PostCategory {
  @ApiProperty({ description: 'Unique identifier for the post category' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ description: 'Category name', example: 'Community News' })
  @Column({ length: 50 })
  name: string;

  @ApiProperty({ description: 'Category description', required: false })
  @Column({ type: 'text', nullable: true })
  description?: string;

  @ApiProperty({ description: 'Icon URL for the category', required: false })
  @Column({ name: 'icon_url', type: 'text', nullable: true })
  iconUrl?: string;

  @ApiProperty({ description: 'Color code for the category', example: '#FF5733' })
  @Column({ name: 'color_code', length: 7, nullable: true })
  colorCode?: string;

  @ApiProperty({ description: 'Whether category is active' })
  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  // Relations
  @OneToMany(() => Post, post => post.category)
  posts: Post[];
}