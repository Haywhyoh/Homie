import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn,
  UpdateDateColumn,
  ManyToMany,
  Index
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { User } from './user.entity';

@Entity('roles')
@Index(['name'], { unique: true })
export class Role {
  @ApiProperty({ description: 'Unique identifier for the role' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'Role name', example: 'admin' })
  @Column({ unique: true, length: 50 })
  name: string;

  @ApiProperty({ description: 'Role display name', example: 'Administrator' })
  @Column({ name: 'display_name', length: 100 })
  displayName: string;

  @ApiProperty({ description: 'Role description', required: false })
  @Column({ type: 'text', nullable: true })
  description?: string;

  @ApiProperty({ description: 'Role permissions as JSON array' })
  @Column({ type: 'jsonb', default: '[]' })
  permissions: string[];

  @ApiProperty({ description: 'Whether role is system defined' })
  @Column({ name: 'is_system', default: false })
  isSystem: boolean;

  @ApiProperty({ description: 'Whether role is active' })
  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @ApiProperty({ description: 'Role creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  // Relations
  @ManyToMany(() => User, user => user.roles)
  users: User[];

  // Helper methods
  hasPermission(permission: string): boolean {
    return this.permissions.includes(permission);
  }

  hasAnyPermission(permissions: string[]): boolean {
    return permissions.some(permission => this.permissions.includes(permission));
  }

  hasAllPermissions(permissions: string[]): boolean {
    return permissions.every(permission => this.permissions.includes(permission));
  }
}