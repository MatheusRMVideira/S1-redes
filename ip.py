from iputils import *
import struct
import random

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        print('IP: Recebido datagrama de camada de enlace, len datagrama: ', len(datagrama))
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            ttl -= 1
            versao = 4 << 4
            ihl = 5
            versao_ihl = versao | ihl
            dscpecn = dscp | ecn
            tamanho = 20 + len(payload)
            dt_original = datagrama
            #Cria o datagrama sem o checksum
            datagrama = struct.pack('!BBHHHBBH', versao_ihl, dscpecn, tamanho, identification, flags, ttl, proto, 0) + str2addr(src_addr) + str2addr(dst_addr)
            checksum = calc_checksum(datagrama[:20])
            #Recria o datagrama com o checksum
            datagrama = struct.pack('!BBHHHBBH', versao_ihl, dscpecn, tamanho, identification, flags, ttl, proto, checksum) + str2addr(src_addr) + str2addr(dst_addr)
            # Tratando corretamente o campo TTL do datagrama
            if ttl > 0:
                print('IP: Enviando datagrama para camada de enlace, len datagrama: ', len(datagrama))
                self.enlace.enviar(datagrama, next_hop)
            else:
                next_hop = self._next_hop(src_addr)
                checksum = 0
                tipo = 11
                payload = dt_original[:28]
                tamanho = 8 + len(payload)
                icmp = struct.pack('!BBHI', tipo, 0, checksum, tamanho) + payload
                checksum = calc_checksum(icmp)
                icmp = struct.pack('!BBHI', tipo, 0, checksum, tamanho) + payload
                print("Enviando ICMP TTL Excedido")
                self.enviar(icmp, src_addr, IPPROTO_ICMP)

    def _next_hop(self, dest_addr):
        dest_addr = struct.unpack('!I', str2addr(dest_addr))
        address = bin(dest_addr[0])[2:].rjust(32, '0')
        verify = -1
        maxPrefix = -1
        for i in range(len(self.tabela)):
            endereco = self.tabela[i][0].split('/')
            bits_destino = endereco[1]
            endereco = struct.unpack('!I', str2addr(endereco[0]))
            endereco = bin(endereco[0])[2:].rjust(32, '0')
            aux = 0
            for j in range(int(bits_destino)):
                if endereco[j] == address[j]:
                    aux += 1
                else:
                    break
            if aux == int(bits_destino) and aux > maxPrefix:
                maxPrefix = aux
                verify = i
        if verify >= 0:
            next_hop = self.tabela[verify][1]
            return next_hop

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela
        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, protocolo = IPPROTO_TCP):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        versao = 4 << 4
        ihl = 5
        versao_ihl = versao | ihl
        dscpecn = 0  | 0
        tamanho = 20 + len(segmento)
        identification = random.randint(0, 65535)
        flags = 0
        ttl = 64
        header = struct.pack('!BBHHHBBH', versao_ihl, dscpecn, tamanho, identification, flags, ttl, protocolo, 0) + str2addr(self.meu_endereco) + str2addr(dest_addr)
        checksum = calc_checksum(header)
        header = struct.pack('!BBHHHBBH', versao_ihl, dscpecn, tamanho, identification, flags, ttl, protocolo, checksum) + str2addr(self.meu_endereco) + str2addr(dest_addr)
        datagrama = header + segmento
        print('IP: Enviando datagrama para camada de enlace, len datagrama: ', len(datagrama))
        self.enlace.enviar(datagrama, next_hop)
