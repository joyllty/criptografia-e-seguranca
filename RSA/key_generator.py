import random
from operations import gcd, modular_inverse, is_prime
 
def generate_prime(min_value, max_value):
    '''
    retorna um número primo aleatório dentro do intervalo min_value e max_value,
    fica sorteando primos no intervalo até encontrar um que passe no teste de primo
    '''
    while True:
        number = random.randint(min_value, max_value)

        if is_prime(number):
            return number
 
def compute_phi(p: int, q: int) -> int:
    '''
    calcula o totiente de n - Euler: phi(n) = (p-1) * (q-1)
 
    o totiente conta quantos números entre 1 e n são coprimos com n
 
    esse valor é mantido em segredo, visrto que quem conhece phi(n) consegue calcular 
    a chave privada a partir da pública

    '''
    return (p - 1) * (q - 1)
 
def choose_e(phi_n):
    '''
    escolhe o expoente público e

    65537 é um valor muito usado no RSA porque é seguro, comum e eficiente
    '''

    e = 65537

    if gcd(e, phi_n) == 1:
        return e

    # se 65537 não funcionar procura outro
    for number in range(3, phi_n, 2):
        if gcd(number, phi_n) == 1:
            return number

    raise ValueError('Não foi possível encontrar um e válido para esse phi(n)')

def generate_keys(min_prime, max_prime):
    '''
    gera e retorna o par de chaves publica e privada do RSA
 
    executa todos os passos da geração de chaves:
    - sorteia dois primos distintos p e q
    - calcula n = p * q
    - calcula phi(n) = (p-1) * (q-1)
    - escolhe e coprimo com phi(n)
    - calcula d = inverso modular de e em phi(n)
    '''
    # gerar dois primos distintos
    p = generate_prime(min_prime, max_prime)
    q = generate_prime(min_prime, max_prime)
 
    # garantir que p e q são diferentes
    while q == p:
        q = generate_prime(min_prime, max_prime)
 
    # calcular n
    n = p * q
 
    # calcular phi(n)
    phi_n = compute_phi(p, q)
 
    # escolher e
    e = choose_e(phi_n)
 
    # calcular d
    d = modular_inverse(e, phi_n)
 
    chave_publica = (n, e)
    chave_privada = (n, d)
 
    return chave_publica, chave_privada
 

