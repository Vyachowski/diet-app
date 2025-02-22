import { ObjectId } from 'mongodb';
import { Column, CreateDateColumn, Entity, Index, ObjectIdColumn } from 'typeorm';

@Entity('users')
export class User {
  @ObjectIdColumn()
  _id: ObjectId;

  @Index({ unique: true })
  @Column()
  email: string;

  @Column()
  password: string;

  @Column({ default: false })
  inactive: boolean;

  @Column()
  activeMenuId: ObjectId;

  @CreateDateColumn()
  createdAt: Date;
}
