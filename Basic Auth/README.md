# Authentication

* [Термины](#Терминология)
* [Причины возникновения](#Причины)
* [Password-based](#Password-based)
  	* Основные уязвимости
* [MFA](#MFA)
	* Основные уязвимости
* [Иные механизмы аутентификации](#Иные)
	* Удержание пользователей в системе
	* Сброс паролей пользователей
		* Отправка паролей по электронной почте
	  	* Сброс паролей с помощью URL-адреса
   	* Изменение паролей пользователей
* [Защита](#Защита)
* [Tools](#Tools)
* [URL](#URL)


# Терминология:

> Аутентификация — это процесс проверки того, что пользователь является тем, за кого себя выдает.
> 
> Авторизация включает в себя проверку того, разрешено ли пользователю что-либо делать.
>
> Многофакторная аутентификация — это аутентификация, при выполнении которой используется не менее двух различных факторов аутентификации.
>
> OTP (One-Time Password) — это способ аутентификации, при котором пользователь получает пароль, доступный только для одного сеанса входа или одной транзакции в информационной системе или приложении. (генерируемый пароль действителен для одной сессии.)

Существует три основных типа аутентификации:

> Что-то, что вы знаете, например пароль или ответ на секретный вопрос. Их иногда называют «факторами знаний».
> 
> Что-то, что у вас есть. Это физический объект, например мобильный телефон или токен безопасности. Их иногда называют «факторами владения».
>
> Что-то, чем вы являетесь или что-то делаете. Например, ваши биометрические данные или модели поведения. Их иногда называют «факторами неотъемлемости».

# Причины возникновения:
	Ошибки в логике
	Слабая защита (brute-force)



# Password-based

> В этом сценарии сам факт знания секретного пароля воспринимается как достаточное доказательство личности пользователя. 
> Следовательно, безопасность сайта будет скомпрометирована, если злоумышленник сможет либо получить, либо угадать учетные данные другого пользователя.

* **Уязвимости**:

	* Возможные brute-force атаки:

  		1. Имен пользователей;
  		2. Подбор паролей;
		3. Перечисление имени пользователя:
  
  				Обратить внимание на:
     
				Коды состояния
				Сообщения об ошибках
				Время ответа
   
  	* Уязвимая защита от brute-force атак

		1. Блокировка учетной записи, к которой пытается получить доступ удаленный пользователь, если он делает слишком много неудачных попыток входа в систему.

  	  	> Создайте список имен пользователей-кандидатов
 		> Определите очень небольшой список паролей
 
  	   			Или
 
  	  	> Использовать подтасовку учетных данных (Использовать словарь пар имя_пользователя:пароль, состоящего из подлинных учетных данных для входа, украденных в результате утечки данных.)
  				
 		2. Блокировка IP-адреса удаленного пользователя, если он делает слишком много попыток входа в систему в быстрой последовательности.

  	   			Включить собственные учетные данные через регулярные промежутки времени в список слов.
  	   
  	   	3. Ограничение скорости пользователя
  	  
  	* HTTP-basic аутентификация
  	  
  	  	> При базовой аутентификации HTTP клиент получает от сервера токен аутентификации, который создается путем объединения имени пользователя и пароля и их кодирования в Base64.
  	  	> Этот токен хранится и управляется браузером, который автоматически добавляет его в заголовок авторизации каждого последующего запроса следующим образом:

			Authorization: Basic base64(username:password)

	Не считается безопасным методом аутентификации:

		Если на сайте также не реализован HSTS
  		Аутентификации HTTP часто не поддерживают защиту от перебора

# MFA

* **Токены двухфакторной аутентификации**

  Многие веб-сайты с высоким уровнем безопасности теперь предоставляют пользователям специальное устройство для этой цели, например токен RSA или клавиатурное устройство, которое вы можете использовать для доступа к своему онлайн-банкингу или рабочему ноутбуку.
  С другой стороны, некоторые веб-сайты отправляют коды подтверждения на мобильный телефон пользователя в виде текстового сообщения. Хотя технически это все еще проверка фактора «что-то, что у вас есть», оно открыто для злоупотреблений.
  
	Во-первых, код передается по SMS, а не генерируется самим устройством. Это создает вероятность перехвата кода.

  	Также существует риск подмены SIM-карты, когда злоумышленник обманным путем получает SIM-карту с номером телефона жертвы. Затем злоумышленник получит все SMS-сообщения, отправленные жертве, включая сообщение, содержащее код подтверждения.

* **Уязвимости**

	* Обход двухфакторной аутентификации:
   
   		> Если пользователю сначала предлагается ввести пароль, а затем на отдельной странице предлагается ввести код подтверждения,
   			пользователь фактически находится в состоянии «вошел в систему» ​​до того, как ввел код подтверждения.
   			В этом случае стоит проверить, можете ли вы сразу перейти на страницы «только для входа» после завершения первого шага аутентификации.
   
	* Неверная логика двухфакторной проверки:
   
   		> Иногда ошибочная логика двухфакторной аутентификации означает, что после того, как пользователь выполнил начальный шаг входа в систему,
   			веб-сайт не может должным образом проверить, что тот же пользователь выполняет второй шаг.
  
   	* brute-force

   	  	> Код подтверждения часто представляет собой простое 4- или 6-значное число. Без адекватной защиты от перебора взломать такой код тривиально.



# Иные механизмы аутентификации 

* **Удержание пользователей в системе**

Эта функциональность часто реализуется путем создания какого-либо токена «запомнить меня», который затем сохраняется в постоянном файле cookie. Поскольку обладание этим файлом cookie позволяет вам фактически обойти весь процесс входа в систему, рекомендуется, чтобы этот файл cookie был непрактичным для угадывания. 

Однако некоторые веб-сайты генерируют этот файл cookie на основе предсказуемого объединения статических значений, таких как имя пользователя и временная метка. 
Некоторые даже используют пароль как часть файла cookie.

Некоторые веб-сайты предполагают, что если файл cookie каким-либо образом зашифрован, его невозможно будет угадать, даже если он использует статические значения. 

Хотя это может быть правдой, если все сделано правильно, наивное «шифрование» файла cookie с использованием простой двусторонней кодировки, такой как Base64, не обеспечивает никакой защиты. 

Используя обычные методы, такие как XSS, злоумышленник может украсть файл cookie «запомнить меня» другого пользователя и определить, как на его основе создается файл cookie.



* **Сброс паролей пользователей**

	* Отправка паролей по электронной почте

		> Электронная почта также обычно не считается безопасной, поскольку почтовые ящики являются постоянными и не предназначены для безопасного хранения конфиденциальной информации.
		> 
  		> Многие пользователи также автоматически синхронизируют свои входящие сообщения между несколькими устройствами по незащищенным каналам.

  	* Сброс паролей с помощью URL-адреса

		> Лучшая реализация этого процесса — создать высокоэнтропийный, трудно угадываемый токен и на его основе создать URL-адрес сброса.
   			В лучшем случае этот URL-адрес не должен содержать подсказок о том, пароль какого пользователя сбрасывается.
			http://website.com/reset-password?token=a0ba0d1cb3b63d13822572fcff1a241895d893f659164d4cc550b421ebdd48a8

		> Однако некоторые веб-сайты не могут повторно проверить токен при отправке формы сброса.
   			В этом случае необходимо посетить форму сброса из своей учетной записи, удалить токен и использовать эту страницу для сброса пароля произвольного пользователя.

		> Если URL-адрес в электронном письме для сброса генерируется динамически, он также может быть уязвим для отравления при сбросе пароля.
   			В этом случае злоумышленник потенциально может украсть токен другого пользователя и с его помощью изменить свой пароль.

   
* **Изменение паролей пользователей**

	> Функция смены пароля может быть особенно опасной, если она позволяет злоумышленнику получить к ней прямой доступ, не входя в систему как пользователь-жертва.
  	>
 	> Например, если имя пользователя указано в скрытом поле, злоумышленник может изменить это значение в запросе, нацеленном на произвольных пользователей.
 	> 
  	> Потенциально это можно использовать для перебора имен пользователей и паролей методом перебора.


Если две записи нового пароля совпадают, учетная запись блокируется. Однако если вы введете два разных новых пароля, в сообщении об ошибке будет просто указано, что текущий пароль неверен. Если вы введете действительный текущий пароль, но два разных новых пароля, появится сообщение «Новые пароли не совпадают». Мы можем использовать это сообщение для перечисления правильных паролей.


# Защита

- Будьте осторожны с учетными данными пользователя
- Не рассчитывать на безопасность пользователей
- Запретить перечисление имен пользователей
- Внедрить надежную защиту от грубой силы
- Трижды проверьте логику проверки.
- Не забывать о дополнительных функциях
- Внедрить правильную многофакторную аутентификацию

___________________________

# Tools

- https://www.kali.org/tools/hydra/
- https://www.kali.org/tools/patator/
- FFUF

___________________________

# URL

- https://portswigger.net/web-security/authentication
- https://www.passwordmonster.com/
- https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md
