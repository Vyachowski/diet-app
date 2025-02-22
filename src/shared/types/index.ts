export enum Environment {
  Development = 'development',
  Production = 'production',
}

export enum Meal {
  Breakfast = 'breakfast',
  Brunch = 'brunch',
  Lunch = 'lunch',
  Snack = 'snack',
  Dinner = 'dinner',
}

export interface Recipe {
  name: string;
  ingredients: { name: string; amountInGramms: number }[];
  calories: number;
  meal: Meal;
  instruction: string;
  image?: string;
}

export type Menu = Record<Meal, Recipe>;
export type GroceryList = { name: string, amountInGramms: number }[];
export type MenuList = { menu: Menu, groceryList: GroceryList }[];
