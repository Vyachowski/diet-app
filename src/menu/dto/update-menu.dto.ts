import { PartialType } from '@nestjs/swagger';
import { CreateMenuDto } from './create-menu.dto';
import { IsJSON, IsString } from 'class-validator';
import { Meal, Recipe } from 'src/shared/types';

export class UpdateMenuDto extends PartialType(CreateMenuDto) {
  @IsString()
  id: string;

  @IsJSON()
  meals: Record<Meal, Recipe>;
}
