import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Post } from './post.entity';

@Entity('post_media')
@Index(['postId'])
export class PostMedia {
  @ApiProperty({ description: 'Unique identifier for the post media' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'Post ID this media belongs to' })
  @Column({ name: 'post_id' })
  postId: string;

  @ApiProperty({ 
    description: 'Type of media', 
    enum: ['image', 'video', 'audio', 'document'],
    example: 'image'
  })
  @Column({ name: 'media_type', length: 20 })
  mediaType: string;

  @ApiProperty({ description: 'URL to the media file' })
  @Column({ name: 'file_url', type: 'text' })
  fileUrl: string;

  @ApiProperty({ description: 'URL to thumbnail (for videos/images)', required: false })
  @Column({ name: 'thumbnail_url', type: 'text', nullable: true })
  thumbnailUrl?: string;

  @ApiProperty({ description: 'File size in bytes', required: false })
  @Column({ name: 'file_size', nullable: true })
  fileSize?: number;

  @ApiProperty({ description: 'MIME type of the file', example: 'image/jpeg' })
  @Column({ name: 'mime_type', length: 100, nullable: true })
  mimeType?: string;

  @ApiProperty({ description: 'Duration in seconds (for video/audio)', required: false })
  @Column({ name: 'duration_seconds', nullable: true })
  durationSeconds?: number;

  @ApiProperty({ description: 'Media dimensions (width/height)', required: false })
  @Column({ type: 'jsonb', nullable: true })
  dimensions?: { width: number; height: number };

  @ApiProperty({ description: 'Order of media in the post' })
  @Column({ name: 'upload_order', default: 0 })
  uploadOrder: number;

  @ApiProperty({ description: 'Media upload timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  // Relations
  @ManyToOne(() => Post, post => post.media, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'post_id' })
  post: Post;

  // Helper methods
  isImage(): boolean {
    return this.mediaType === 'image';
  }

  isVideo(): boolean {
    return this.mediaType === 'video';
  }

  getFormattedFileSize(): string {
    if (!this.fileSize) return 'Unknown';
    
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (this.fileSize === 0) return '0 Bytes';
    
    const i = Math.floor(Math.log(this.fileSize) / Math.log(1024));
    return Math.round(this.fileSize / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }
}