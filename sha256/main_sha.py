from sha256 import sha256
import sys


def generate_hash_string(message):
    '''
    recebe uma string, converte para bytes e gera o hash SHA-256
    '''

    message_bytes = message.encode('utf-8')
    generated_hash = sha256(message_bytes)

    return generated_hash

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("===== COMANDO =====")
        print("Gerar hash: python main.py gerar 'sua_mensagem'")
    
    else: 
        command = sys.argv[1]
    
        if command == "gerar":
            message = sys.argv[2]
            generated_hash = generate_hash_string(message)
            print(f">> Mensagem: {message}")
            print(f">> Hash SHA-256: {generated_hash}")

        else:
            print(f">> Comando '{command}' não reconhecido.")