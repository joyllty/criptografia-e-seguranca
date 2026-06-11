'''
execução do chat
'''

import argparse
import threading
import time
import requests
from key_generator import generate_keys

from chat_service import PRIMOS_A, PRIMOS_B, generate_chat_keys, find_public_key, send_message, iniciate_server


def main():
    parser = argparse.ArgumentParser()
    
    # pegar os argumentos digitados no terminal
    # nome, sua porta e porta destino
    parser.add_argument('--name', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--peer-port', type=int, required=True)

    args = parser.parse_args()

    name = args.name
    port = args.port
    peer_url = f'http://localhost:{args.peer_port}'

    print('>> Gerando chaves RSA\n')

    if port == 5001:
        p, q = PRIMOS_A
    else:
        p, q = PRIMOS_B

    # gera o conjunto de chaves de uma pessoa
    public_key, private_key = generate_chat_keys(p, q)

    # cria a thread que roda o servidor
    servidor_thread = threading.Thread(
        target=iniciate_server,
        args=(name, port, public_key, private_key),
        daemon=True
    )

    servidor_thread.start()

    print(f'>> {name} rodando em http://localhost:{port}')

    peer_public_key = None

    # buscando a chave publica da outra aplicação
    while peer_public_key is None:
        try:
            peer_public_key = find_public_key(peer_url)
        except requests.exceptions.ConnectionError:
            time.sleep(2)

    print('>> Chave pública da outra aplicação recebida.')
    print('>> Chat iniciado')
    print('>> Digite /sair para encerrar\n')

    while True:
        message = input('> ')
        # digitar /sair encerra
        if message.lower() == '/sair':
            break

        try:
            # fica enviando mensagem
            send_message(name, message, peer_url, peer_public_key)

        except Exception as erro:
            print(f'>> Erro ao enviar mensagem: {erro}')


if __name__ == '__main__':
    main()