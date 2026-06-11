MASK32 = 0xFFFFFFFF

def right_rotation(x, n):
    '''Rotação circular à direita de x por n bits (32 bits).'''
    return ((x >> n) | (x << (32 - n))) & MASK32


def shift_right(x, n):
    '''
    Shift lógico à direita de x por n bits
    '''
    return (x >> n) & MASK32


def sigma0(x):
    '''
    σ0: usada no message schedule (expansão do W) 
    '''
    return right_rotation(x, 7) ^ right_rotation(x, 18) ^ shift_right(x, 3)


def sigma1(x):
    '''
    σ1: usada no message schedule (expansão do W)
    '''
    return right_rotation(x, 17) ^ right_rotation(x, 19) ^ shift_right(x, 10)


def cap_sigma0(x):
    '''
    Σ0: usada na compressão, aplicada sobre a variável "a"
    '''
    return right_rotation(x, 2) ^ right_rotation(x, 13) ^ right_rotation(x, 22)


def cap_sigma1(x):
    '''
    Σ1: usada na compressão, aplicada sobre a variável "e"
    '''
    return right_rotation(x, 6) ^ right_rotation(x, 11) ^ right_rotation(x, 25)


def ch(e, f, g):
    '''
    Choice: bits de e escolhem entre bits de f (1) ou g (0)
    '''
    return (e & f) ^ (~e & g) & MASK32


def maj(a, b, c):
    '''
    Majority: resultado é 1 se pelo menos dois dos três bits forem 1
    '''
    return (a & b) ^ (a & c) ^ (b & c)


def add32(*args):
    '''soma módulo 2^32 de n valores'''
    return sum(args) & MASK32