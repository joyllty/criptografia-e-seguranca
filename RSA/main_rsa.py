from operations import modular_inverse
from rsa import encrypt, decrypt
import sys

# primos grandes fixos
# usei primos grandes porque OAEP com SHA-256 precisa de um n grande
p = 4149515568880992958512407863691161151012446232242436899995657329690652811412908146399707048947103794288197886611300789182395151075411775307886874834113963687061181803401509523698459

q = 8299031137761985917024815727382322302024892464484873799991314659381305622825816292799414097894207588576395773222601578364790302150823550615773749668227927374122363606803019047425151


# calcula n
n = p * q

# calcula phi(n)
phi_n = (p - 1) * (q - 1)

# expoente público comum no RSA
e = 65537

# calcula o expoente privado d
d = modular_inverse(e, phi_n)


# monta as chaves
chave_publica = (n, e)
chave_privada = (n, d)


mensagem_original = sys.argv[1]

print('===== DEMONSTRANDO RSA =====')
print()

print(f'>> Mensagem original: {mensagem_original}\n')

print(f'>> Tamanho de n: {n.bit_length()} bits\n')

print(f'Chaves públicas: \nn = {n}\ne = {e}\n')

print(f'Chaves privadas: \nn = {n}\nd = {d}\n')


# cifra a mensagem 
texto_cifrado = encrypt(mensagem_original, chave_publica)

print(f'>> Mensagem cifrado: \n{texto_cifrado}\n')

# decifra a mensagem 
mensagem_decifrada_bytes = decrypt(texto_cifrado, chave_privada)

# converte decrypt pra string
mensagem_decifrada = mensagem_decifrada_bytes.decode('utf-8')

print(f'>> Mensagem decifrada: {mensagem_decifrada}\n')

# confere se a mensagem original e a decifrada são iguais
if mensagem_original == mensagem_decifrada:
    print('>> Resultado: FUNCIONOU, são iguais')
else:
    print('>> Resultado: DEU ERRO, a mensagem decifrada tá diferente')