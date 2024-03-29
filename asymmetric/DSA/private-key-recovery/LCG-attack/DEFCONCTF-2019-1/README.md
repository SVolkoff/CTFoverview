# tania 

#### DEF CON CTF Qualifier 2019

### Условия задания

Дан файл: [tania](tania). Требуется получить флаг. 

### Уязвимость

После реверса данного ELF-файла обнаруживается, что система подписывает и выполняет команды по следующим правилам:

1. Команды подписываются алгоритмом цифровой подписи (DSA)
    - Система позволяет получить только две подписи: `(r1, s1)`, `(r2, s2)`- с помощью двух команд `m1`, `m2`:
      - `m1 = "the rules are the rules, no complaints"`
      - `m2 = "reyammer can change the rules"`
    - Случайное одноразовое число `k` генерируется линейный конгруэнтным методом (LCG)
2. Команды выполняются (через `system()`) при успешной проверке подписи.

Линейный конгруэнтный метод не обладает криптографической стойкостью. Поэтому алгоритм цифровой подписи с одноразовыми числами, сгенерированными линейный конгруэнтным методом ненадёжен. 

Для решения [линейных конгруэнтных уравнений](dss-lcg.pdf) с различным модулем требуется и задания целевого вектора `Y` построить 
решетку `B` уравнений конгруэнции. После построения решетки `B` запускается 
[LLL алгоритм](lll.pdf) и алгоритм ближайшей плоскости Бабаи, для получения секретного ключа `x`, 
а также одноразовых значений `k1` и `k2`, которые были использованы для подписи команд `m1` и `m2`. 
Зная закрытый ключ x и используя случайный одноразовый номер k, можно получить правильную пару (r,s) и подписать m = "cat flag".

Решение линейных конгруэнтных уравнений: [LCG.sage](LCG.sage) 
Подписывает команду cat flag: [solve.py](solve.py)  