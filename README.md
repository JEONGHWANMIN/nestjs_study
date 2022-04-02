# NestJs Study

# NestJs

install

`npm i -g @nestjs/cli`

프로젝트 생성

`nest new project-name`

npm install @nestjs/core (core 때문에 에러가 난다면 )

---

실행 : npm run start:dev

app.module.ts [진입점 역할을 해준다.]

Controller → 라우팅 처리

Service → 관련 로직 처리

간단하게 생각해서

Module 등록되어 있다면 Controller 가 라우팅 처리를 받아서 Service에서 로직 처리를 해준다.

---

# Install

**Module 설치**

`nest g module boards`

**Controller 설치**

`nest g controller boards --no-spec`

—no-spec : 테트스 코드 생성 x

컨트롤러는 Handler 사용한다 . (@Post , @Patch , @Get , @Delete)

@Body body 부분으로 를 받는다.

Provider : service or repository 사용하려면 등록되어 있어야 한다.

**Service 설치**

`nest g service boards —no-spec`

Service를 Controller에서 사용하려면 Serivce를 타입부분에 넣어준다.

**DTO(Data Transfer Object)**

**Class Or interface 로 생성**

```jsx
import { IsNotEmpty } from 'class-validator';

export class CreateBoardDto {
  @IsNotEmpty()
  title: string;

  @IsNotEmpty()
  description: string;
}
```

- 데이터 유효성 검사
- 안정적인 검사

Controller , Service 부분 사용

## **Pipe : @UsePipes()**

데이터가 컨트롤러 메소드에 들어가기 직전에 작동한다.

- Data Validation (유효성 검사)
- Data TransFormation (입력데이터 원하는 형식으로 변환)

필요 라이브러리 ( class-validator , class-transformer )

dto → IsNotEmpty() 사용 , 이렇게만 하면 연결이 안되어 있으니 Pipe로 연결해 줘야 한다.

커스텀 파이프 구현 방법

1. PipeTransform 인터페이스를 implements 받아야 한다.
2. transform( value , metadata ) 메소드를 필요로 하게 된다.

---

## TypeORM (Object Relational Mapping )

Nodejs 에서 실행되고 ,TypeScript 로 작성괸 객체 관계형 매퍼 라이브러리

ORM

→ 객체와 관계형 데이터베이스를 자동으로 변형 및 연결하는 작업

NestJs TypeORM 사용하기 위한 라이브러리 (NestJs 에서 지원하는 버전 확인 필요)

1. `@nestjs/typeorm` → nestjs 에서 TypeORM 연동시켜주는 모듈
2. `typeorm` → TypeORM 모듈
3. `pg` → Postgres 모듈

## **nestjs typeorm 적용하는 방법**

src / configs / typeorm.config.ts 파일 생성

ex)

```jsx
import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export const TypeORMConfig: TypeOrmModuleOptions = {
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'postgres',
  password: 'postgres',
  database: 'board-app',
  entities: [__dirname + '/../**/*.entity.{js,ts}'],
  synchronize: true,
};
```

app.module 에 typerom 설정을 등록 시켜 줘야 한다.

```jsx
@Module({
  imports: [BoardsModule, TypeOrmModule.forRoot(TypeORMConfig)],
})
```

entity생성 → Contorller , Service , Repository 사용된다.

```jsx
import { Entity, BaseEntity, Column, PrimaryGeneratedColumn } from 'typeorm';
import { BoardStatus } from './board.model';

@Entity()
export class Board extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;
  @Column()
  title: string;
  @Column()
  description: string;
  @Column()
  status: BoardStatus;
}
```

## **Repository**

엔티티 개체와 함께 사용되며 , 엔티티 찿기 업데이트 , 삭제 , 삽입 등이 이루어 진다.

[TypeORM - Amazing ORM for TypeScript and JavaScript (ES7, ES6, ES5). Supports MySQL, PostgreSQL, MariaDB, SQLite, MS SQL Server, Oracle, WebSQL databases. Works in NodeJS, Browser, Ionic, Cordova and Electron platforms.](https://typeorm.io/)

[Repository | typeorm](https://typeorm.delightful.studio/classes/_repository_repository_.repository.html)

![Untitled](NestJs%209bfd1/Untitled.png)

board.repository.ts 파일 생성

```jsx
import { EntityRepository, Repository } from 'typeorm';
import { Board } from './board.entity';

@EntityRepository(Board)
export class BoardRepository extends Repository<Board> {}
```

board Module import

```jsx
imports: [TypeOrmModule.forFeature([BoardRepository])],
```

---

## **Service Repository Connection**

```jsx
@Injectable()
export class BoardsService {
  constructor(
    @InjectRepository(BoardRepository)
    private boardRepository: BoardRepository,
  ) {}
```

1. @InjectRepository(BoardRepository) 데코레이터를 이용해서 주입한다고 선언 해준다.
2. 사용하고자 하는 Repository를 constructor 에 넣어준다. 성장에 서비스를 주입하듯이 private 로 만들어 준다.

TypeORM methods 사용가능

TypeORM CRUD gogo

---

## **AUTH**

1. Module
2. Contoller ( 생성자 함수로 Service 연결)
3. Service

3개 생성해 준다.

1. Entity 생성
2. Repository 생성
3. auth.model : imports : [] 작성
4. Service 부분에서 Constructor 로 Repository 등록해준다.

**DTO 유효성 체크**

```jsx
import { IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class AuthCredentialDto {
  @IsString()
  @MinLength(4)
  @MaxLength(20)
  username: string;
  @IsString()
  @MinLength(4)
  @MaxLength(20)
  @Matches(/^[a-zA-Z0-9]*$/, {
    message: 'password only accept english and number',
  })
  password: string;
}
```

**Entity 고유의 유니크값 설정하는법**

```jsx
import {
  BaseEntity,
  Column,
  Entity,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';

@Entity()
@Unique(['username'])
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;
  @Column()
  username: string;
  @Column()
  password: string;
}
```

## 비밀번호 암호화 하기 (라이브러리 이용)

`npm i bcryptjs —-save`

→ 암호화하는( 알고리즘 + 키 ) 두가지 사용한다.

// Salt 값 + 유저 비밀번호를 합쳐서 Hash 해준다.

비밀번호 데이터 베이스 저장하는 방법

비밀번호 → 암호화 → 복호화 → 비밀번호

```jsx
import * as bcrypt from 'bcryptjs';
// bcrypt
const salt = await bcrypt.genSalt();
const hashedPassword = await bcrypt.hash(password, salt);
```

암호화된 비밀번호 비교하기

1. 해당 user값을 받아온다.
2. 유저가 보낸 password 랑 user값에 저장된 hashed 된 비밀번호를 비교한다.

```jsx
const { username, password } = authCredentialDto;
const user = await this.userRepository.findOne({
  username,
});
if (user && (await bcrypt.compare(password, user.password))) {
  return user.username;
} else {
  throw new UnauthorizedException('login falid');
}
```

## JWT (Json Web Token)

당사장간에 정보를 JSON객체로 안전하게 전송하기 위한 방식

구조 : (Header , Payload , Verify Signature)

1. Header : 토큰에 대한 알고리즘
2. Payload : 유저정보 , 만료기간 , 주제
3. Verify Signature : 위조 여부를 확인하는 부분

필요한 라이브러리 (4개)

1. @nestjs/jwt
2. @nestjs/passport
3. passport
4. passport-jwt

JWT 사용하려면 모듈에 등록을 해줘야 한다.

Auth 에서 사용할거기 때문에 auth 모듈에 imports 시켜준다.

```jsx
JwtModule.register({
      secret: 'Secret1234',
      signOptions: {
        expiresIn: 60 * 60,
      },
    }),
```

Secret - 토큰을 만들 때 이용하는 Secret 텍스트

ExpiresIn : 정해진 시간 이후에 토큰이 유효하지 않게 되는 옵션

passport 사용하려면 모듈에 등록을 해줘야 한다.

Auth 에서 사용할거기 때문에 auth 모듈에 imports 시켜준다.

```jsx
PassportModule.register({ defaultStrategy: 'jwt' }),
```

## LogIn 성공시 토큰 생성해 주기

Service 부분에 생성자(Constructor) 부분에 등록을 해서 사용을 해줘야 한다.

`private jwtService : JwtService`

유저 아이디 비밀번호 확인 후 유저가 맞다면 토큰을 줘야한다.

```jsx
const payload = { username };
const accessToken = await this.jwtService.sign(payload);
return { accessToken };
```

## 요청 온 토큰이 유요한지 확인하고 데이터 베이스 확인 작업

- Browser는 토큰을 가지고 있다가 필요시에 꺼내서 Header 부분에 넣어서 토큰을 보내준다.

필요 라이브러리 `@types/passport-jwt`

1. 라이브러리 설치
2. jwt.strategy.ts 파일 생성

```jsx
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { User } from './user.entity';
import { UserRepository } from './user.repository';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  // Token에 있는 유저정보를 DB 데이터랑 비교하기 위해서 필요
  constructor(
    @InjectRepository(UserRepository)
    private userRepository: UserRepository,
  ) {
    super({
      secretOrKey: 'Secret1234',
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    });
  }

  async validate(payload) {
    const { username } = payload;
    const user: User = await this.userRepository.findOne({ username });
    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
```

코드설명

1. 토큰을 DB랑 비교하기 위해서 생성자 → userRepository @InjectRepository를 해준다.
2. 생성자 함수 함수 내에서 super() 로 1. sercetKey랑 2. jwt토큰이 어디로부터 담겨 오는지 명시해준다.
3. validate 메서드를 사용해서 (payload) 값을 넣어주고 payload에 있는 데이터가 DB에 있으면 유저를 없으면 에러를 던져준다.

위 토큰 확인과정을 거치려면 auth.moudule.ts에 등록을 해줘야 한다.

```jsx
@Module({
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [JwtStrategy, PassportModule],
  imports: [
    TypeOrmModule.forFeature([UserRepository]),
    JwtModule.register({
      secret: 'Secret1234',
      signOptions: {
        expiresIn: 60 * 60,
      },
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }),
  ],
})
export class AuthModule {}
```

Provider 부분에 JwtStrategy를 등록해주고

외부에서도 사용하기 위해서 exports 해준다.

## Nestjs Middleware

> Pipes

- validation 체크

> Filters

- 오류 처리 미들웨어

> Guards

- 인증에 관한 미들 웨어

> Interceptors

- 응답 매핑 , 캐시 관리 와 함께 요청 로깅과 같은 전후 미들 웨어

Token으로 인증을 하려면 인증에 관한 미들웨어인 UseGuards()를 사용해야 한다.

useGuards() 인자로는 AuthGuard를 넣어준다.

@Req() req → console.log()를 찍어보면 req.user에 유저정보가 담겨 있다.

## Custom Decorator 만드는 방법

get-user.decorator.ts 파일 생성

```jsx
export const GetUser = createParamDecorator(
  (data, ctx: ExecutionContext): User => {
    const req = ctx.switchToHttp().getRequest();
    return req.user;
  },
);
```

확인해보기

```jsx
@Post('/test')
  @UseGuards(AuthGuard())
  test(@GetUser() user: User) {
    console.log('user', user);
  }
```

Board 에서 인증된 유저만 게시글 작성을하려면 BoardMoudule에서 AuthModule을 imports 해줘야한다.

## 유저와 게시물 데이터 관계 형성

관계 형성을 위해서는 엔티티간에 서로간의 필드를 넣어줘야 한다.

OneToMany RelationShip

User → board1 , board2 , board3 여러개 만들수 있다.

게시물 입장에서는

ManyToOne RelationShip

userEntity

```jsx
import { type, userInfo } from 'os';
import { Board } from 'src/boards/board.entity';
import {
  BaseEntity,
  Column,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';

@Entity()
@Unique(['username'])
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;
  @Column()
  username: string;
  @Column()
  password: string;

  @OneToMany((type) => Board, (board) => board.user, { eager: true })
  boards: Board[];
}
```

boardEntity

```jsx
import { User } from 'src/auth/user.entity';
import {
  Entity,
  BaseEntity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
} from 'typeorm';
import { BoardStatus } from './board-status.enum';

@Entity()
export class Board extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;
  @Column()
  title: string;
  @Column()
  description: string;
  @Column()
  status: BoardStatus;
  @ManyToOne((type) => User, (user) => user.boards, { eager: false })
  user: User;
}
```

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikh3YW5NaW4xIiwiaWF0IjoxNjQ4NzEwNzkwLCJleHAiOjE2NDg3MTQzOTB9.isbi4lupv3AsNdhhiC4U2-NNmB_1ynrCqkYTvQ0J8OM

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikh3YW5NaW4yIiwiaWF0IjoxNjQ4NzEwODkxLCJleHAiOjE2NDg3MTQ0OTF9.cALjSEQydtONJ8U0whIXKrikRZx3H_FDe6Nd1unc2HI

## 로그 남기기

로그 종류

1. Log - 중요한 정보의 범용 로깅
2. Warning - 치명적이거나 파괴적이지 않은 처리되지 않은 문제
3. Error - 치명적이거나 파괴적인 처리되지 않은 문제
4. Debug - 오류 발생시 로직을 디버그 하는데 도움이 되는 유용한 정보 - (개발자용)
5. Verbose - 응용 프로그램의 동작에 대한 통찰력을 제공하는 정보 (운영자용)

express → winston이란 모듈을 사용해서 로그를 처리한다.

nestjs → built-in 된 logger 클래스가 있다.
