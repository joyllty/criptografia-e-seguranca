'''
lógica do chat
- gerar chaves
- buscar chave pública da outra aplicação
- enviar mensagem
- receber mensagem
- iniciar servidor HTTP
'''


import json
import requests
# servidor http simples
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from rsa import encrypt, decrypt
from operations import modular_inverse



PRIMOS_A = (
    9651566154695749015278030981470556370982155849803634849148848269496253252693581903351061606098798601494517414468243343088607379593928818582807657079671269,
    6829014452139066233624299112510988626994899767407098330414280613426532147409664882973740859535948390463357084229354221356217151160919845646312327499255971
)

PRIMOS_B = (
    8140180136387916314007287773788940382051163992428411762915658185723983315617017941673963551167479734029683752915939446619074501930960416056152191174782127,
    10573695572293360326797657372271345297649981243376289080090049087317637401709497810128030620619546501629420740761240898194020718731176414370506380502050531
)

def generate_chat_keys(p, q):
    '''
    gera as chaves RSA usando primos fixos para demonstração
    '''

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537
    d = modular_inverse(e, phi_n)

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key

def find_public_key(peer_url):
    '''
    busca a chave pública da outra aplicação
    '''

    responde = requests.get(f'{peer_url}/public-key')
    # pega a resposta e transforma em json
    data = responde.json()

    # converte os numeros em string pra int
    n = int(data['n'])
    e = int(data['e'])

    return (n, e)


def send_message(nome, message, peer_url, peer_public_key):
    '''
    criptografa a mensagem com a chave pública do destinatário e envia para o webhook /message
    '''

    # criptografa a mensagem com a chave publica do destino
    ciphertext = encrypt(message, peer_public_key)

    # monta os dados
    data = {
        'from': nome,
        'ciphertext': str(ciphertext)
    }

    requests.post(f'{peer_url}/message', json=data)


def create_handler(name, public_key, private_key):
    '''
    cria o handler HTTP da aplicação / comportamento do servidor
    '''

    # classe que define o que o servidor faz com as requisições
    class ChatHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            # pegar a chave publica
            if self.path == '/public-key':
                n, e = public_key
                # dados mandados na requisição
                data = {
                    'name': name,
                    'n': str(n),
                    'e': str(e)
                }

                # transforma em json
                response = json.dumps(data).encode('utf-8')

                # envia resposta com status 200
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(response)

            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            # enviar mensagem
            if self.path == '/message':
                size = int(self.headers['Content-Length'])
                body = self.rfile.read(size)

                # transoforma o json em dicionario
                data = json.loads(body.decode('utf-8'))

                # pega o remetente
                remetente = data['from']
                # pega o texto cifrado e converte pra int
                ciphertext = int(data['ciphertext'])

                try:
                    # decifra a mensagem, passando a chave privada
                    mensage_bytes = decrypt(ciphertext, private_key)
                    # converte pra texto
                    mensage = mensage_bytes.decode('utf-8')
                    
                    # mostra a mensagem
                    print(f'[{remetente}] {mensage}')
                    print('> ', end='', flush=True)

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'>>Mensagem recebida')

                except Exception as erro:
                    print(f'\n>> Erro ao descriptografar: {erro}')

                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(str(erro).encode('utf-8'))

            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            # remove logs automáticos do servidor
            return

    return ChatHandler


def iniciate_server(name, port, public_key, private_key):
    '''
    inicia o servidor HTTP local
    '''
    
    # cria e liga o servidor
    handler = create_handler(name, public_key, private_key)

    # comportamento do servidor
    servidor = ThreadingHTTPServer(('localhost', port), handler)

    # cria o servidor na porta
    servidor.serve_forever()