import secrets
from sha256.sha256 import sha256


def mgf1(seed, length):
    '''
    Mask Generation Function 1
    recebe uma seed e gera uma máscara de bytes com o tamanho desejado

    no OAEP a máscara é usada para embaralhar o bloco da mensagem e a 
    seed aleatória

    retorna -> máscara de bytes com tamanho igual a length
    '''
    result = b''
    counter = 0

    # continua gerando hashes até atingir o tamanho necessário
    while len(result) < length:
        # o contador precisa ser convertido para 4 bytes em big endian - padrão do MGF1
        c = counter.to_bytes(4, 'big')

        # junta a seed com o contador e aplica SHA-256
        result += sha256(seed + c) # minha função

        counter += 1

    # corta o resultado para ser exatamente o tamanho pedido
    return result[:length]


def xor_bytes(a, b):
    '''
    basicamente fazer xor entre bytes
    '''
    return bytes(x ^ y for x, y in zip(a, b))


def oaep_encode(message, k, label=b''):
    '''
    aplica o padding OAEP na mensagem antes de passar para o RSA
    o RSA não deve cifrar a mensagem diretamente, então é passado pelo oaep

    k -> tamanho da chave RSA em bytes
    retorna -> mensagem codificada com oaep ainda em bytes
    '''
    # sha256 sempre gera 32 bytes
    h_len = 32  

    # fórmula do tamanho máximo da mensagem no OAEP:
    # tamanho máximo = k - 2*h_len - 2
    max_len = k - 2 * h_len - 2

    # verifica se a mensagem cabe no bloco rsa usando oaep
    if len(message) > max_len:
        raise ValueError('>> Mensagem grande demais para esse tamanho de chave RSA')

    # mesmo que o label seja vazio o oaep usa o hash dele
    l_hash = sha256(label)

    # padding para completar o tamanho do bloco
    ps = b'\x00' * (max_len - len(message))

    # datablock
    # hash(label) | zeros | 0x01 | mensagem
    db = l_hash + ps + b'\x01' + message

    # seed aleatória de 32 bytes
    seed = secrets.token_bytes(h_len)

    # gera uma máscara para o bloco DB
    db_mask = mgf1(seed, k - h_len - 1)

    # aplica XOR entre o DB e a máscara
    masked_db = xor_bytes(db, db_mask)

    # gera uma máscara para a seed usando o masked_db
    seed_mask = mgf1(masked_db, h_len)

    # aplica XOR entre a seed e a máscara
    masked_seed = xor_bytes(seed, seed_mask)

    # monta a mensagem final codificada:
    # 0x00 || masked_seed || masked_db
    em = b'\x00' + masked_seed + masked_db

    return em


def encode_message_to_int(message, n):
    '''
    converte a mensagem com oaep para um inteiro para ser usado no RSA

    etapas:
    1 - se a mensagem for string transforma em bytes
    2 - calcula o tamanho da chave RSA em bytes
    3 - aplica OAEP na mensagem
    4 - converte o resultado final de bytes para int
    '''

    # se a mensagem vier como texto normal converte para bytes
    if isinstance(message, str):
        message = message.encode("utf-8")

    # calcula o tamanho de n em bytes
    k = (n.bit_length() + 7) // 8

    # aplica OAEP na mensagem
    encoded_message = oaep_encode(message, k)

    # converte os bytes codificados para int
    return int.from_bytes(encoded_message, "big")


def oaep_decode(encoded_message, k, label=b''):
    '''
    remove o padding depois que o RSA descriptografou o texto cifrado

    encoded_message -> bloco OAEP em bytes
    k -> tamanho da chave RSA em bytes
    label -> mesmo label usado no oaep_encode, normalmente vazio

    retorna -> mensagem original em bytes
    '''

    h_len = 32

    # o bloco precisa ter exatamente o tamanho da chave RSA em bytes
    if len(encoded_message) != k:
        raise ValueError('>> Bloco OAEP com tamanho inválido')

    # o primeiro byte do OAEP deve ser 0x00
    if encoded_message[0] != 0:
        raise ValueError('>> Bloco OAEP inválido')

    # separa o bloco:
    # EM = 0x00 | masked_seed | masked_db
    masked_seed = encoded_message[1 : 1 + h_len]
    masked_db = encoded_message[1 + h_len :]

    # refaz a máscara da seed usando o masked_db
    seed_mask = mgf1(masked_db, h_len)

    # desfaz o XOR para recuperar a seed original
    seed = xor_bytes(masked_seed, seed_mask)

    # refaz a máscara do DB usando a seed recuperada
    db_mask = mgf1(seed, k - h_len - 1)

    # desfaz o XOR para recuperar o DB original
    db = xor_bytes(masked_db, db_mask)

    # calcula novamente o hash do label
    l_hash = sha256(label)

    # pega o hash do label que veio dentro do DB
    l_hash_recuperado = db[:h_len]

    # se os hashes forem diferentes o bloco é inválido
    if l_hash_recuperado != l_hash:
        raise ValueError('>> Hash do label inválido')

    # depois do hash vem:
    # zeros | 0x01 | mensagem
    rest = db[h_len:]

    # procura o byte 0x01 que separa o padding da mensagem
    try:
        indice_separador = rest.index(b'\x01')
    except ValueError:
        raise ValueError('>> Separador 0x01 não encontrado no OAEP')

    # antes do separador só podem existir bytes zero
    padding = rest[:indice_separador]

    if padding != b'\x00' * len(padding):
        raise ValueError('>> Padding OAEP inválido')

    # tudo depois do separador é a mensagem original
    message = rest[indice_separador + 1:]

    return message


def decode_int_to_message(m, n):
    '''
    converte o int recuperado pelo RSA de volta para mensagem original

    etapas:
    1- calcula o tamanho da chave em bytes
    2- converte o int para bytes
    3- remove o OAEP
    4- retorna a mensagem original em bytes
    '''

    # calcula o tamanho de n em bytes
    k = (n.bit_length() + 7) // 8

    # converte o inteiro recuperado pelo RSA para bytes
    encoded_message = m.to_bytes(k, 'big')

    # remove o OAEP e recupera a mensagem original
    return oaep_decode(encoded_message, k)