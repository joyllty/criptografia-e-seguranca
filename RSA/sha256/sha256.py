from sha256.constants import H0, K
from sha256.operations import sigma0, sigma1, cap_sigma0, cap_sigma1, ch, maj, add32


def pad_message(message):
    ''' 
    aplica padding de 0s no bloco de mensagem para pra se tornar múltiplo de 512 bits
    retorna o bloco com padding
    '''
    length_in_bits = len(message) * 8

    # adiciona o byte 0x80 
    message += b'\x80'

    # adiciona bytes 0x00 até restar exatamente 8 bytes para o fim do bloco
    while len(message) % 64 != 56:
        message += b'\x00'

    # adiciona o comprimento original em bits como inteiro de 64 bits big-endian
    message += length_in_bits.to_bytes(8, byteorder='big')

    return message


def build_schedule(block):
    '''
    expansão do bloco de mensagem em 64 words de 32 bits(4 bytes): W[0 -> 63] (message schedule)
    as primeiras 16 words (0 a 15) vem do próprio bloco de mensagem
    a partir da 17 (w16) elas serão calculadas pelas próprias words já existentes
    '''

    w = []

    # pega as 16 primeiras words do bloco em big-endian, pulando de 4 em 4 bytes
    for i in range(16):
        word = int.from_bytes(block[i*4 : i*4+4], byteorder='big')
        w.append(word)

    # calcula as 48 words que restam com uma soma modular de 32 bits (add32), onde a cada iteração, as words usadas 
    # para o cálculo serão alteradas dessa maneira:
    '''
    - w[i-16]: 16 posições atras
    - sigma0(w[i-15]): aplica sigma0(2 rotações e 1 shift) na word 15 posições atras
    - w[i-7]: 7 posições atras
    - sigma1(w[i-2]): aplica sigma1(2 rotações e 1 shift) na word 2 posições atras
    '''
    for i in range(16, 64):
        word = add32(w[i-16], sigma0(w[i-15]), w[i-7], sigma1(w[i-2]))
        w.append(word)

    # retorna lista de words
    return w


def compression(block, state):
    '''
    executa as 64 rodadas de compressão sobre um bloco de mensagem e retorna o novo estado gerado
    
    state - h0 até h7 -> registradores do hash, depois do primeiro bloco de mensagem/words, eles deixam de ser os valores iniciais, utilizando o state do bloco anterior pra gerar outro state
    '''

    # expansão do bloco de mensagem em 64 words
    w = build_schedule(block)

    # inicializa as variáveis de trabalho com o estado atual do hash
    a, b, c, d, e, f, g, h = state

    # 64 rodadas de compressão
    for i in range(64):
        # temp1/ soma de:
        # h -> ultima variavel de trabalho, 
        # cap_sigma1 -> rotações aplicadas em "e", 
        # choice entre "f" e "g" usando "e", 
        # k[i] -> constante da rodada atual, 
        # w[i] -> word atual   
        t1 = add32(h, cap_sigma1(e), ch(e, f, g), K[i], w[i])

        # temp2/ soma de:
        # cap_sigma0 -> rotações aplicadas em "a"
        # maj(a,b,c) -> bit majoritário entre a b e c
        t2 = add32(cap_sigma0(a), maj(a, b, c))

        # aqui desloca as variaveis de trabalho pra frente 
        h = g
        g = f
        f = e
        e = add32(d, t1) # soma de d com temp1
        d = c
        c = b
        b = a
        a = add32(t1, t2) # soma de temp1 e temp2

    # soma o resultado das variaveis de trabalho com o state anterior do hash
    new_state = [
        add32(state[0], a),
        add32(state[1], b),
        add32(state[2], c),
        add32(state[3], d),
        add32(state[4], e),
        add32(state[5], f),
        add32(state[6], g),
        add32(state[7], h),
    ]

    # retorna o novo state gerado
    return new_state


def sha256(message):
    '''
    função principal: recebe uma mensagem em bytes e retorna o hash SHA-256 em hexadecimal
    '''
    message = pad_message(message)

    # copia os valores iniciais para nao modificar a constante original
    state = H0[:]

    # processa cada bloco de 64 bytes sequencialmente
    for i in range(0, len(message), 64):
        block = message[i : i+64]
        state = compression(block, state)

    # concatena os 8 valores do state final em hexadecimal

    # alterado para retornar bytes pro rsa
    return b''.join(value.to_bytes(4, 'big') for value in state)