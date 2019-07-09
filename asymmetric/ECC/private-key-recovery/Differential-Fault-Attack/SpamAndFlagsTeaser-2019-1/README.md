# Secure PW DB


#### SpamAndFlags Teaser 2019

### Условия задания

Дана веб-страница, на которой можно проверить, если некий пароль утек. 
Требуется найти флаг.

### Уязвимость

Исходный код страницы открыт. Ее принцип работы заключается в следующем:
-	Пользователь предоставляет пароль;
-	Этот пароль преобразуется в точку `Q` на эллиптической кривой `E` на стороне клиента;
-	Эта точка умножается на случайный клиентский секретный ключ `enc_key` на стороне клиента,
 так что сервер имеет доступ к точке пароля только в зашифрованном виде: `R = enc_key*Q`;
-	Точка `R` шифруется с использованием секретного ключа `k` на стороне сервера путем вычисления новой точки `S = k*R`;
-	Используя первую букву отправленного пользователем пароля, сервер получает список всех паролей, начинающийся с 
этой буквы, и возвращает зашифрованные версии этих паролей;
-	После этого точка `S` расшифровывается делением на клиентский секретный ключ `enc_key`, т.е. умножением точки `S` 
на `modinv(enc_key, E.order())`;
-	После этого зашифрованные пароли, полученные от сервера, сравниваются с имеющейся точкой, если любой из них совпадает, 
значит, пароль был в базе данных сервера.

Уязвимость возникает из-за того, что сервер фактически не проверяет, является ли точка, которую предоставляет пользователь,
 допустимой точкой на кривой `E`. Пользователь отправляет некоторую точку, `R` и сервер просто рассчитывает `k*R` для нее.
 И если посмотреть, как выполняются вычисления, то выясняется, что параметр кривой `B` не используется в скалярном умножении.
Это означает, что можно проводить атаку, описанную в статье [18800131.pdf](18800131.pdf).

При этом создается новая эллиптическая кривая `E'`, используя новое значение для параметра `B`, такое, чтобы порядок новой 
кривой имел небольшой по значению делитель `r`. Затем необходимо отправить какую-нибудь точку подгруппы порядка `r` на сервер. Тогда можно
 будет вычислить дискретный логарифм для небольшой подгруппы порядка `r` и восстановить `k mod r`, где `k` - секретный ключ сервера.
Затем можно повторить этот процесс для разных значений `r` и разных кривых `E'` и собрать систему отношений `ci = k mod ri`. 
Как только их будет достаточно, можно будет воспользоваться китайской теоремой об остатках, чтобы восстановить значение `k` 
(для этого нужно достаточно пар, `(ci, ri)`, чтобы `r1*r2*...*rn >= k`)
Проделав это, получаем секретный ключ `k = 86962807399445295025648724453367621898`.
Далее просто берутся зашифрованные пароли с сервера и расшифровываются. Поскольку параметры кривой и секретный 
ключ известны, можно просто рассчитать `modinv(k, E.order())` и умножить зашифрованные пароли на это значение. Ответом будет 
 x-координата точки результата напечатанная в виде строки.
 
Решение: [ecc.sage](ecc.sage) 