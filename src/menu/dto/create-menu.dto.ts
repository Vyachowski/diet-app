import { ApiProperty } from '@nestjs/swagger';
import { IsJSON } from 'class-validator';
import { MenuList } from 'src/shared/data';
import { Meal, Recipe } from 'src/shared/types';

export class CreateMenuDto {
  @ApiProperty({
    type: 'object',
    example: MenuList.at(0).menu,
    additionalProperties: null,
  })
  @IsJSON()
  menu: Record<Meal, Recipe>;
}
