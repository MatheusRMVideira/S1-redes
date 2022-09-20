#!/usr/bin/env python3

# Note que não é mais necessário fazer a gambiarra com o iptables que era feita
# nas etapas anteriores, pois agora nosso código Python vai assumir o controle
# de TODAS as camadas da rede!

# Este é um exemplo de um programa que faz eco, ou seja, envia de volta para
# o cliente tudo que for recebido em uma conexão.

import asyncio
from camadafisica import PTY
from tcp import Servidor   # copie o arquivo do Trabalho 2
from ip import IP  # copie o arquivo do Trabalho 3
from slip import CamadaEnlace
from irc import *

DEBUG = True

linha_serial = PTY()
outra_ponta = '192.168.123.1'
nossa_ponta = '192.168.123.2'

print('Para conectar a outra ponta da camada física, execute:')
print('  sudo slattach -v -p slip {}'.format(linha_serial.pty_name))
print('  sudo ifconfig sl0 {} pointopoint {}'.format(outra_ponta, nossa_ponta))
print()
print('O serviço ficará acessível no endereço {}'.format(nossa_ponta))
print()

enlace = CamadaEnlace({outra_ponta: linha_serial})
rede = IP(enlace)
rede.definir_endereco_host(nossa_ponta)
rede.definir_tabela_encaminhamento([
    ('0.0.0.0/0', outra_ponta)
])
servidor = Servidor(rede, 7000)

servidor.registrar_monitor_de_conexoes_aceitas(conexao_aceita)
asyncio.get_event_loop().run_forever()
