import { Injectable, OnModuleInit } from '@nestjs/common';
import { DataSource, ObjectId } from 'typeorm';
import { Menu } from './entities/menu.entity';
import { MenuList } from 'src/shared/data';
import { CreateMenuDto } from './dto/create-menu.dto';
import { UpdateMenuDto } from './dto/update-menu.dto';

@Injectable()
export class MenuService implements OnModuleInit {
  constructor(private dataSource: DataSource) {}

  async onModuleInit() {
    try {
      const count = await this.dataSource.manager.count(Menu);

      if (count > 0) {
        console.log('Menu collection exists and contains records.');
      } else {
        console.log(
          'Menu collection exists but is empty, data will be created.',
        );

        const newMenu = this.dataSource.mongoManager.create(Menu, MenuList.at(0).menu);
        const result = await this.dataSource.manager.save(newMenu);

        console.log('Data was created:', result);
      }
    } catch {
      console.error('Error checking menu collection, data will be created.');

      const newMenu = this.dataSource.mongoManager.create(Menu, MenuList.at(0).menu);
      const result = await this.dataSource.manager.save(newMenu);

      console.log('Data was created:', result);
    }
  }

  async create(createMenuDto: CreateMenuDto) {
    const menu = this.dataSource.mongoManager.create(Menu, createMenuDto.menu);
    return await this.dataSource.mongoManager.save(menu);
  }

  async findAll() {
    return await this.dataSource.mongoManager.find(Menu);
  }

  async findOne(id: number) {
    return await this.dataSource.mongoManager.findOneBy(Menu, id);
  }

  async update(id: number, updateMenuDto: UpdateMenuDto) {
    const editingMenu = await this.dataSource.mongoManager.findOneBy(Menu, id);

    if (editingMenu) {
      throw new Error(`Menu with id ${id} not found`);
    }

    const updatedMenu = {
      ...editingMenu,
      ...updateMenuDto,
    };

    const createdMenu = this.dataSource.mongoManager.create(Menu, updatedMenu);
    return await this.dataSource.mongoManager.save(createdMenu);
  }

  async remove(id: number) {
    const objectId = new ObjectId(id);

    const result = await this.dataSource.mongoManager.deleteOne(Menu, {
      _id: objectId,
    });

    if (result.deletedCount === 0) {
      throw new Error(`Menu with id ${id} not found`);
    }

    return { message: `Menu with id ${id} has been removed` };
  }
}
