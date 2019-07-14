# Hastad

#### UIUCTF - 2018 
 
### Условия задания

В задании дано два текстовых файла: [ciphertexts.txt](ciphertexts.txt), [moduli.txt](moduli.txt) и упоминается, что `е = 3`.  

### Уязвимость

Т.к. шифрование сообщения по схеме RSA происходит следующим образом: `C = M^e mod N`, то в случае с открытой экспонентой `e = 3`, 
получение шифртекстов выглядит так:

`C1 = M^3 mod N1`
`C2 = M^3 mod N2`
`C3 = M^3 mod N3`

Зная, что `N1`, `N2`, `N3` взаимно просты, можем применить к шифртекстам китайскую теорему об остатках.

В итоге получается некоторое `C`, кубический корень из которого дает искомое сообщение `M`.

`C' = M3 mod N1*N2*N3`

Т.к. `M` меньше каждого из трёх модулей `Ni`, то справедливо равенство: `C = M3`.
В задании дано 3 `Ni` и 15 `Ci`. Нужно найти только 3 `Ci` для реализации [атаки Хастада](chennagiri.pdf).
Таким образом, можно перебрать все перестановки `Сi`, чтобы найти необходимые пары `(Ci,Ni)` и получить флаг.

Решение: [solve.py](solve.py)