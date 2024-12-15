import { Meal, Recipe } from './types';

const basicMenu: { meals: Record<Meal, Recipe> } = {
  meals: {
    [Meal.Breakfast]: {
      name: 'Scrambled Eggs with Avocado',
      ingredients: [
        { name: 'egg', amountInGramms: 200 },
        { name: 'avocado', amountInGramms: 100 },
        { name: 'spinach', amountInGramms: 50 },
      ],
      meal: Meal.Breakfast,
      instruction:
        'Whisk eggs and cook in a non-stick pan. Slice avocado and serve with sautéed spinach.',
      calories: 452,
      image:
        'https://www.tasteofhome.com/wp-content/uploads/2024/04/Avocado-Scrambled-Eggs_FT24_10302_ST_0515_2.jpg',
    },
    [Meal.Brunch]: {
      name: 'Cottage Cheese with Walnuts',
      ingredients: [
        { name: 'cottage cheese', amountInGramms: 200 }, // ~180 kcal
        { name: 'walnuts', amountInGramms: 20 }, // ~130 kcal
      ],
      meal: Meal.Brunch,
      instruction: 'Serve cottage cheese topped with chopped walnuts.',
      calories: 310,
      image:
        'https://www.hsnstore.eu/blog/wp-content/uploads/sites/5/2020/02/cottage-cheese-honey-wanuts-768x384.jpg',
    },
    [Meal.Lunch]: {
      name: 'Grilled Chicken with Quinoa and Vegetables',
      ingredients: [
        { name: 'chicken breast', amountInGramms: 150 }, // ~165 kcal
        { name: 'quinoa', amountInGramms: 120 }, // ~220 kcal
        { name: 'broccoli', amountInGramms: 100 }, // ~34 kcal
        { name: 'carrots', amountInGramms: 80 }, // ~33 kcal
      ],
      meal: Meal.Lunch,
      instruction:
        'Grill chicken breast. Cook quinoa according to package instructions. Steam broccoli and carrots.',
      calories: 452,
      image:
        'https://www.completelydelicious.com/wp-content/uploads/2023/05/grilled-chicken-quinoa-salad-5-768x1024.jpg',
    },
    [Meal.Snack]: {
      name: 'Greek Yogurt with Berries and Nuts',
      ingredients: [
        { name: 'greek yogurt', amountInGramms: 150 }, // ~100 kcal
        { name: 'blueberries', amountInGramms: 50 }, // ~28 kcal
        { name: 'almonds', amountInGramms: 20 }, // ~120 kcal
      ],
      meal: Meal.Snack,
      instruction:
        'Mix Greek yogurt with fresh blueberries and top with chopped almonds.',
      calories: 248,
      image:
        'https://lh3.ggpht.com/_BizpeaUzxq8/Sc2CnomPpeI/AAAAAAAAA9g/zwyx8yREB4o/s800/greek-yogurt.jpg',
    },
    [Meal.Dinner]: {
      name: 'Salmon with Sweet Potato and Asparagus',
      ingredients: [
        { name: 'salmon', amountInGramms: 150 }, // ~250 kcal
        { name: 'sweet potato', amountInGramms: 200 }, // ~180 kcal
        { name: 'asparagus', amountInGramms: 100 }, // ~20 kcal
      ],
      meal: Meal.Dinner,
      instruction:
        'Bake salmon with olive oil and herbs. Roast sweet potato and asparagus.',
      calories: 450,
      image:
        'https://catzinthekitchen.com/wp-content/uploads/2016/11/One-Pan-Salmon-PIN.jpg',
    },
  },
};

export const groceryList = [
  { name: 'egg', amountInGramms: 200 },
  { name: 'avocado', amountInGramms: 100 },
  { name: 'spinach', amountInGramms: 50 },
  { name: 'cottage cheese', amountInGramms: 200 },
  { name: 'walnuts', amountInGramms: 20 },
  { name: 'chicken breast', amountInGramms: 150 },
  { name: 'quinoa', amountInGramms: 120 },
  { name: 'broccoli', amountInGramms: 100 },
  { name: 'carrots', amountInGramms: 80 },
  { name: 'greek yogurt', amountInGramms: 150 },
  { name: 'blueberries', amountInGramms: 50 },
  { name: 'almonds', amountInGramms: 20 },
  { name: 'salmon', amountInGramms: 150 },
  { name: 'sweet potato', amountInGramms: 200 },
  { name: 'asparagus', amountInGramms: 100 },
];

export default basicMenu;
