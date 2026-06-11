from operations import mod_pow
from text_encoding import encode_message_to_int, decode_int_to_message

def encrypt(message, public_key):
    '''
    cifra uma mensagem de texto usando a chave pública
 
    passos:
    1- aplica OAEP na mensagem via encode_message_to_int(usa MGF1 + SHA256 + seed aleatória)
    2- converte o resultado para inteiro
    3- aplica C = M^e mod n
 
    retorna -> número inteiro representando o texto cifrado
 
    Atenção: a mensagem convertida em inteiro deve ser menor que n.
    Para mensagens longas, seria necessário dividir em blocos.

    '''
    # chaves publicas
    n, e = public_key
    m = encode_message_to_int(message, n)
 
    if m >= n:
        raise ValueError(
            f'>> Mensagem codificada maior que n ({m} >= {n})'
            f'>> Use uma chave maior.'
        )
 
    return mod_pow(m, e, n)


def decrypt(ciphertext, private_key):
    '''
    decifra um texto cifrado usando a chave privada
 
    retorna o inteiro decifrado como bloco OAEP, que posteriormente terá seu
    padding removido
 
    passos:
    1- aplica M = C^d mod n
    2- retorna o int resultante
    
    retorna -> int com o bloco OAEP decifrado
    '''
    # chaves privadas
    n, d = private_key

    # aplica a operação do RSA
    # M = C^d mod n
    m = mod_pow(ciphertext, d, n)

    # remove o OAEP e recupera a mensagem original
    return decode_int_to_message(m, n)