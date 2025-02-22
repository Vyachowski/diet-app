import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { join } from 'path';
import { AppModule } from './app.module';
import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import flash from 'connect-flash';
import { AuthService } from './auth/auth.service';

enum ConfigRecord {
  dbUrl = 'MONGODB_URL',
  dbName = 'MONGODB_NAME',
  envType = 'ENV',
  appPort = 'PORT',
}

const configureSwagger = (app: INestApplication) => {
  const config = new DocumentBuilder()
    .setTitle('Clean diet app API docs')
    .setDescription('Clean diet API description')
    .setVersion('1.0')
    .addTag('Diet')
    .build();

  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, documentFactory);
};

const getAppConfig = (configService) => {
  const DEFAULT_APP_PORT = 3000;

  return {
    dbUrl: configService.get(ConfigRecord.dbUrl),
    dbName: configService.get(ConfigRecord.dbName),
    envType: configService.get(ConfigRecord.envType),
    appPort: configService.get(ConfigRecord.appPort) ?? DEFAULT_APP_PORT,
  };
};

const checkAppConfig = (config) => {
  Object.entries(config).forEach(([key, value]) => {
    if (!value) {
      throw new Error(
        `Missing configuration: "${key}" is not defined or empty.`,
      );
    }
  });
};

(async () => {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const configService = app.get(ConfigService);
  const authService = app.get(AuthService);

  try {
    const appConfig = getAppConfig(configService);

    checkAppConfig(appConfig);
    configureSwagger(app);

    app.use(cookieParser());
    app.useStaticAssets(join(__dirname, '..', 'public'));
    app.use(
      session({
        secret: configService.get('JWT_SECRET'),
        resave: false,
        saveUninitialized: false,
      }),
    );

    app.use((req, res, next) => {
      const token = req.cookies?.access_token;

      if (token) {
        const decodedUser = authService.verifyJwtToken(token);
        if (decodedUser) {
          req.user = decodedUser;
        }
      }
      res.locals.authorised = !!req.user;
      res.locals.user = req.user;

      next();
    });

    app.use(flash());
    app.setBaseViewsDir(join(__dirname, '..', 'views'));
    app.setViewEngine('pug');
    await app.listen(appConfig.appPort);
  } catch (e) {
    console.error('Application failed to start:', e.message);
    console.error(e.stack);
    process.exit(1);
  }
})();
