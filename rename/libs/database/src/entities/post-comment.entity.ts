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
import { Post } from './post.entity';
import { User } from './user.entity';

@Entity('post_comments')
@Index(['postId'])
@Index(['userId'])
@Index(['parentCommentId'])
export class PostComment {
  @ApiProperty({ description: 'Unique identifier for the comment' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'Post ID this comment belongs to' })
  @Column({ name: 'post_id' })
  postId: string;

  @ApiProperty({ description: 'User ID who made the comment' })
  @Column({ name: 'user_id' })
  userId: string;

  @ApiProperty({ description: 'Parent comment ID for replies', required: false })
  @Column({ name: 'parent_comment_id', nullable: true })
  parentCommentId?: string;

  @ApiProperty({ description: 'Comment content' })
  @Column({ type: 'text' })
  content: string;

  @ApiProperty({ description: 'Whether comment is approved' })
  @Column({ name: 'is_approved', default: true })
  isApproved: boolean;

  @ApiProperty({ description: 'Comment creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  // Relations
  @ManyToOne(() => Post, post => post.comments, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'post_id' })
  post: Post;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ManyToOne(() => PostComment, comment => comment.replies, { nullable: true })
  @JoinColumn({ name: 'parent_comment_id' })
  parentComment?: PostComment;

  @OneToMany(() => PostComment, comment => comment.parentComment)
  replies: PostComment[];

  // Helper methods
  isReply(): boolean {
    return !!this.parentCommentId;
  }
}