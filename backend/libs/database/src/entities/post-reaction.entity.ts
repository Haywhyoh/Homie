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
import { Post } from './post.entity';
import { User } from './user.entity';

@Entity('post_reactions')
@Index(['postId'])
@Index(['userId'])
@Unique(['postId', 'userId'])
export class PostReaction {
  @ApiProperty({ description: 'Unique identifier for the post reaction' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'Post ID this reaction belongs to' })
  @Column({ name: 'post_id' })
  postId: string;

  @ApiProperty({ description: 'User ID who reacted' })
  @Column({ name: 'user_id' })
  userId: string;

  @ApiProperty({ 
    description: 'Type of reaction', 
    enum: ['like', 'love', 'laugh', 'angry', 'sad'],
    example: 'like'
  })
  @Column({ name: 'reaction_type', length: 20, default: 'like' })
  reactionType: string;

  @ApiProperty({ description: 'Reaction creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  // Relations
  @ManyToOne(() => Post, post => post.reactions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'post_id' })
  post: Post;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;
}