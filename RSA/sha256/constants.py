'''
constantes dos valores iniciais do hash e constantes de rodada
numeros primos
aqui sao gerados os numeros primos com generate_primes() 
'''

import math

# mascara binaria de 32 bits, serve pra descartar tudo que passe acima de 32 bits
MASK32 = 0xFFFFFFFF

def fractional_bits(value):
    '''
    pega a parte fracionaria de um numero, multiplica por 2^32 e retorna os 32 bits inferiores
    '''
    # só a parte fracionaria
    fractional = value % 1

    # retorna um inteiro de 32 bits
    return int(fractional * (2**32)) & MASK32


def generate_primes(n):
    '''
    gera os n primeiros números primos
    '''
    primes = []
    current = 2  # numero atual 

    while len(primes) < n:
        is_prime = True

        for p in primes:
            if current % p == 0: # se o resto da divisão entre o número primo e o número atual for 0, não é primo
                is_prime = False
                break
        
        # se for primo adiciona na lista de primos
        if is_prime:
            primes.append(current)

        current += 1
    
    # retorna os numeros primos
    return primes


def generate_h0():
    '''
    gera os valores iniciais H0, pegando a parte fracionária da raiz quadrada dos 8 primeiros numeros primos
    e multiplicando eles por 2^32
    '''

    # gera os 8 numeros primos
    primes = generate_primes(8)

    # pra cada primo, calcula a raiz quadrada, pega os bits fracionarios tranformados em inteiros e adiciona
    # em uma lista
    return [fractional_bits(math.sqrt(p)) for p in primes]


def generate_k():
    '''
    gera as constantes K, pegando a parte fracionária da raiz cúbica dos 64 primeiros numeros primos e 
    multiplicando eles por 2^32
    '''
    # gera os 64 numeros primos
    primes = generate_primes(64)

    # pra cada primo, calcula a raiz cubica, pega os bits fracionarios transformados em inteiros e adiciona
    # em uma lista    
    return [fractional_bits(math.pow(p, 1/3)) for p in primes]


# ========== constantes de fato ==========
# valores iniciais do hash
H0 = generate_h0()

# constantes de rodada
K = generate_k()
