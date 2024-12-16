import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  ParseIntPipe,
} from '@nestjs/common';
import { MenuService } from './menu.service';
import { CreateMenuDto } from './dto/create-menu.dto';
import { ApiBody, ApiTags } from '@nestjs/swagger';
import { UpdateMenuDto } from './dto/update-menu.dto';

@ApiTags('Menu')
@Controller('api/menu')
export class MenuController {
  constructor(private readonly menuService: MenuService) {}

  @Post()
  @ApiBody({ type: CreateMenuDto })
  create(@Body() createMenuDto: CreateMenuDto) {
    return this.menuService?.create(createMenuDto);
  }

  @Get()
  findAll() {
    return this.menuService?.findAll();
  }

  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.menuService.findOne(id);
  }

  @Patch(':id')
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateMenuDto: UpdateMenuDto,
  ) {
    return this.menuService.update(id, updateMenuDto);
  }

  @Delete(':id')
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.menuService.remove(id);
  }
}
