
def gcd(a, b):
    '''
    retorna o máximo divisor comum entre a e b usando o algoritmo de Euclides iterativo
 
    o algoritmo se baseia na propriedade: mdc(a, b) == mdc(b, a mod b)
    repetimos até b chegar a 0,  nesse ponto, a é a resposta
 
    Exemplos:
        gcd(48, 18) -> 6
        gcd(7, 160) -> 1   (são coprimos = mdc= 1)
    '''
    while b != 0:
        a, b = b, a % b
    return a
 

def extended_gcd(a, b):
    '''
    retorna (mdc, x, y) tal que:
        a*x + b*y == mdc(a, b)
 
    essa é a versão estendida do algoritmo de Euclides, os coeficientes x e y são o que nos permite calcular
    o inverso modular. ela é recursiva, volta calculando os coeficentes, seguindo a lógica do mdc normal

    como funciona:
    caso base: se b == 0, então mdc = a, x = 1, y = 0
                pois a*1 + 0*0 = a
    passo recursivo: resolve para (b, a mod b) e substitui de volta.
 
    Exemplos:
        extended_gcd(7, 160) -> (1, 23, -1)
        Verificação: 7*23 + 160*(-1) = 161 - 160 = 1  
    '''
    if b == 0:
        return a, 1, 0
    
    mdc, x1, y1 = extended_gcd(b, a % b)
 
    x = y1
    y = x1 - (a // b) * y1
 
    return mdc, x, y
 
 
def modular_inverse(e, phi_n):
    '''
    retorna d tal que:
        e * d ≡ 1 (mod phi_n)

    um numero que multiplicado por e apresenta resto 1 ao ser divido por phi(n)
 
    no RSA isso calcula o expoente privado d a partir do expoente público 'e' e do totiente de Euler phi(n)
 
    usa o extended_gcd internamente: como mdc(e, phi_n) == 1,
    sabemos que e*x + phi_n*y == 1, logo e*x ≡ 1 (mod phi_n),
    ou seja, x é o nosso inverso. Garantimos que o resultado
    seja positivo aplicando x mod phi_n no final.
 
    lança ValueError se e e phi_n não forem coprimos
 
    Exemplos:
        modular_inverse(7, 160) -> 23
        Verificação: 7 * 23 = 161 ≡ 1 (mod 160)  
    '''
    mdc, x, y = extended_gcd(e, phi_n)
 
    if mdc != 1:
        raise ValueError(
            f'Inverso modular não existe: mdc({e}, {phi_n}) = {mdc} '
            f'e e phi_n precisam ser coprimos'
        )
 
    return x % phi_n

def is_prime(n):
    '''
    verifica se um número é primo de forma mais eficiente
    testando divisores só até a raiz quadrada de n
    '''

    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    divisor = 3

    while divisor * divisor <= n:
        if n % divisor == 0:
            return False

        divisor += 2

    return True

def mod_pow(base, exp, mod):
    '''
    retorna (base ** exp) % mod de forma eficiente

 
    usa o algoritmo de exponenciação rápida (square-and-multiply), que executa em O(log exp) 
    multiplicações em vez de O(exp), essencial para chaves RSA de 2048+ bits
 
    Exemplo: base^13, onde 13 = 1101 em binário
        resultado = 1
        bit 1:  resultado = 1^2 * base   = base
        bit 1:  resultado = base^2 * base = base^3
        bit 0:  resultado = (base^3)^2    = base^6
        bit 1:  resultado = (base^6)^2 * base = base^13  

    Todas as multiplicações são feitas mod `mod` a cada passo,
    mantendo os números pequenos durante todo o processo.

Exemplos:
    mod_pow(2, 10, 1000) -> 24    (1024 % 1000)
    mod_pow(88, 7, 187)  -> 11    (cifragem com p=11, q=17)
    mod_pow(11, 23, 187) -> 88    (decifragem — volta ao original)
    '''
    if mod == 1:
        return 0
    if exp < 0:
        raise ValueError('>> Expoentes negativos não são suportados.')
 
    resultado = 1
    base = base % mod
 
    while exp > 0:
        if exp % 2 == 1:
            resultado = (resultado * base) % mod
        base = (base * base) % mod
        exp //= 2
 
    return resultado


