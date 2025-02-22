import { ObjectId } from 'mongodb';
import { Meal, Recipe } from 'src/shared/types';
import { Column, CreateDateColumn, Entity, ObjectIdColumn } from 'typeorm';

@Entity('menus')
export class Menu {
  @ObjectIdColumn()
  _id: ObjectId;

  @Column()
  [Meal.Breakfast]: Recipe;

  @Column()
  [Meal.Brunch]: Recipe;

  @Column()
  [Meal.Lunch]: Recipe;

  @Column()
  [Meal.Snack]: Recipe;

  @Column()
  [Meal.Dinner]: Recipe;

  @CreateDateColumn()
  createdAt: Date;
}
