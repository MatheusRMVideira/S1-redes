import asyncio
from tcputils import *
import random
import math
import time

class Servidor:
    #Inicialização do servidor
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    #Inicialização da conexão
    def iniciar_conexao(self, id_conexao, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)
        src_addr, src_port, dst_addr, dst_port = id_conexao
        ack_no = seq_no + 1
        seq_no = random.randint(40, 0xfff)

        # Envia um pacote de resposta para confirmar a conexão
        cabecalho = make_header(dst_port, src_port, seq_no, ack_no, FLAGS_SYN | FLAGS_ACK)
        self.rede.enviar(fix_checksum(cabecalho, src_addr, dst_addr), src_addr)
        print("TCP: Enviando SYN-ACK para %s:%d" % (src_addr, src_port))
        return Conexao(self, id_conexao, seq_no + 1, ack_no)

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        print('TCP: Recebido pacote de %s:%d para %s:%d' % (src_addr, src_port, dst_addr, dst_port))

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return

        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        # Se a flag for SYN, inicializa uma nova conexão
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = self.iniciar_conexao(id_conexao, segment)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('TCP: %s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))



class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):

        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = None
        self.window_size = 1
        
        #Variaveis para o controle de retransmissão
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.ultimo_enviado = seq_no
        self.ultimo_seq = None
        self.nao_enviados = b''
        self.nao_confirmados = b''

        #Variaveis para o timeout e rtt
        self.primeiro_rtt = True
        self.tempo_inicio = None
        self.tempo_fim = None
        self.timeout_interval = 1
        self.sample_rtt = None
        self.estimated_rtt = None
        self.dev_rtt = None
        
        #Variaveis de estado
        self.retransmitindo = False
        self.desconectando = False


    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        if self.ack_no == seq_no: # Se o pacote for o esperado

            #Inicia o processo de desconexão
            if (flags & FLAGS_FIN) == FLAGS_FIN and not self.desconectando:
                self.desconectando = True
                self.callback(self, b'')
                self.ack_no += 1
                cabecalho = make_header( dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN | FLAGS_ACK)
                print("TCP: Enviando FIN-ACK para %s:%d" % (src_addr, src_port))
                self.servidor.rede.enviar(fix_checksum(cabecalho, src_addr, dst_addr), src_addr)
                return
            
            #Finaliza o processo de desconexão
            if (flags & FLAGS_ACK) == FLAGS_ACK and self.desconectando:
                print("TCP: Conexão finalizada")
                self.servidor.conexoes.pop(self.id_conexao)
                return

            if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.ultimo_enviado:
                self.nao_confirmados = self.nao_confirmados[ack_no - self.ultimo_enviado:]
                self.ultimo_enviado = ack_no
                print("TCP: ACK recebido para %s:%d" % (src_addr, src_port))
                if self.nao_confirmados:
                    self.iniciar_timer()
                else:
                    self.parar_timer()
                    if not self.retransmitindo:
                        self.tempo_fim = time.time()
                        self.calcular_rtt()

            if self.ultimo_seq == ack_no:
                self.window_size += 1
                self.enviar_pendente()

            self.retransmitindo = False
            self.ack_no += len(payload)

            #Se tiver algum payload, envia o pacote para a camada de aplicação
            if len(payload) > 0:
                print("TCP: Enviando pacote para a camada de aplicação, len payload: %d" % len(payload))
                dados = make_header(src_port, dst_port, self.seq_no, self.ack_no, flags)
                self.servidor.rede.enviar(fix_checksum(dados, src_addr,dst_addr),dst_addr)
                self.callback(self, payload)

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        #Limita o tamanho do pacote para o tamanho da janela
        self.nao_enviados += dados
        prontos_para_envio = self.nao_enviados[:(self.window_size * MSS)]
        self.nao_enviados = self.nao_enviados[(self.window_size * MSS):]

        #Atualiza o numero de sequencia do pacote enviado para o ultimo pacote
        self.ultimo_seq = self.seq_no + len(prontos_para_envio)

        quant_de_segmentos = math.ceil(len(prontos_para_envio) / MSS)

        for i in range(quant_de_segmentos):
            msg = prontos_para_envio[i*MSS:(i+1)*MSS]
            self.enviar_ack(msg)


    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        Envia um pacote FIN
        """
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        cabecalho = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN)
        print("TCP: Enviando FIN para %s:%d" % (src_addr, src_port))
        self.servidor.rede.enviar(fix_checksum(cabecalho, dst_addr, src_addr), src_addr)
    
    def enviar_ack(self, payload):
        dst_addr, dst_port, src_addr, src_port = self.id_conexao
        seq_no = None
        #Se estiver retransmitindo, o numero de sequencia do pacote é o ultimo enviado
        if self.retransmitindo:
            seq_no = self.ultimo_enviado
        else:
            seq_no = self.seq_no
            self.seq_no += len(payload)
            #Adiciona o pacote a lista de nao confirmados
            self.nao_confirmados = self.nao_confirmados + payload
        cabecalho = make_header(src_port, dst_port, seq_no, self.ack_no, FLAGS_ACK)
        print("TCP: Enviando ACK para %s:%d, len payload: %d" % (src_addr, src_port, len(payload)))
        self.servidor.rede.enviar(fix_checksum(cabecalho + payload, src_addr, dst_addr), dst_addr)
        #Se nao tiver um timer, inicia o timer de timeout
        if self.timer is None:
            self.tempo_inicio = time.time()
            self.iniciar_timer()

    def enviar_pendente(self):
        """
        Envia os pacotes pendentes
        """
        tamanho_pendentes = (self.window_size * MSS ) - len(self.nao_confirmados)

        #Caso tenha pendentes
        if tamanho_pendentes > 0:
            prontos_para_envio = self.nao_enviados[:tamanho_pendentes]
            if len(prontos_para_envio) == 0:
                return
            self.nao_enviados = self.nao_enviados[tamanho_pendentes:]
            self.ultimo_seq = self.seq_no + len(prontos_para_envio)

            #Divide em segmentos de tamanho MSS
            numero_de_segmentos = math.ceil(len(prontos_para_envio) / MSS)
            for i in range(numero_de_segmentos):
                msg = prontos_para_envio[i*MSS:(i+1)*MSS]
                self.enviar_ack(msg)

    def iniciar_timer(self):
        self.parar_timer()
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self.timeout)

    def parar_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def timeout(self):
        self.timer = None
        self.retransmitir()
        self.iniciar_timer()

    def retransmitir(self):
        """
        Retransmite os pacotes nao confirmados
        """
        self.retransmitindo = True
        self.window_size = self.window_size // 2
        comprimento = min(MSS, len(self.nao_confirmados))
        msg = self.nao_confirmados[:comprimento]
        self.enviar_ack(msg)

    def calcular_rtt(self):
        """
        Calcula o RTT
        """
        alfa = 0.125
        beta = 0.25

        self.sample_rtt = self.tempo_fim - self.tempo_inicio

        if self.primeiro_rtt:
            self.primeiro_rtt = not self.primeiro_rtt
            
            self.estimated_rtt = self.sample_rtt
            self.dev_rtt = self.sample_rtt / 2
        else:
            self.estimated_rtt = (1 - alfa) * self.estimated_rtt + alfa * self.sample_rtt
            self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(self.sample_rtt - self.estimated_rtt)

        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt
