from sha256 import sha256
import sys

def read_file(filepath):
    # abre o arquivo em modo binario
    with open(filepath, 'rb') as f:
        content = f.read()
    # passa o conteudo do arquivo para o sha256 e retorna o hash
    return sha256(content)


def generate_hash(filepath):
    # lê o arquivo e calcula seu hash
    generated_hash = read_file(filepath)
    print(f'Arquivo: {filepath}')
    print(f'Hash SHA-256: {generated_hash}')


def validate_file(filepath, provided_hash):
    # recalcula o hash do arquivo pra comparar com o hash fornecido
    calculated_hash = read_file(filepath)

    print(f'Arquivo: {filepath}')
    print(f'Hash fornecido: {provided_hash}')
    print(f'Hash calculado: {calculated_hash}')

    # se os hashes forem iguais o arquivo não foi alterado desde que o hash foi gerado
    if calculated_hash == provided_hash:
        print('\n>> Resultado: ARQUIVO AUTÊNTICO')
    else:
        print('\n>> Resultado: ARQUIVO INVÁLIDO')


if __name__ == "__main__":
    '''
    filepath = input('>> Informe o caminho do arquivo: ')
    generate_hash(filepath)
 
    hash_fornecido = input('\n>> Informe o hash para validação: ')
    validate_file(filepath, hash_fornecido)
    '''

    # exibe as instruções de uso se nenhum argumento for passado
    if len(sys.argv) < 3:
        print("===== COMANDOS =====")
        print("Gerar hash:       python main.py gerar <arquivo>")
        print("Validar arquivo:  python main.py validar <arquivo> <hash>")
    
    else: 
        command = sys.argv[1]
    
        if command == "gerar":
            generate_hash(filepath=sys.argv[2])
    
        elif command == "validar":
            if len(sys.argv) < 4:
                print(">> Erro: informe o arquivo e o hash para validação.")
            validate_file(filepath=sys.argv[2], provided_hash=sys.argv[3])
    
        else:
            print(f">> Comando '{command}' não reconhecido.")