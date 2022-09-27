#!/usr/bin/env python3
import asyncio
from tcp import Servidor
import re

# key: conexao, value: apelido
apelidos = {} #utlizado no passo 4
# key: canal, value: lista_conexao
canais = {} #utilizado no passo 6


def validar_nome(nome): #Valida o nome do usuario
    return re.match(br'^[a-zA-Z][a-zA-Z0-9_-]*$', nome) is not None

def converttostr(input_seq, separador): #Converte sequencia em string
	for i in range(len(input_seq)):
		if i == 0:
			final_str = b'%s ' % input_seq[i] 
		elif i == (len(input_seq)-1):
			final_str = final_str + (b'%s' % input_seq[i])
		else:
			final_str = final_str + (b'%s ' % input_seq[i])
	return final_str

def sair(conexao):
	### passo 8 ###
	
	# Criando lista de envio de mensagem
	lista_pessoas_canal = []
	for key, valor in canais.items():
		if conexao in valor:
			for pessoa in valor:
				lista_pessoas_canal.append(pessoa)
	
	if lista_pessoas_canal != []:
		
		# Remove duplicados
		lista_pessoas_canal = list(dict.fromkeys(lista_pessoas_canal))
		
		# Remover pessoa que esta saindo da lista
		lista_pessoas_canal.remove(conexao)

		
	# Envia mensagem de quit para os outros usuarios no mesmo canal
	for destinatario in lista_pessoas_canal:
			destinatario.enviar(b':%s QUIT :Connection closed\r\n' % apelidos[conexao])
			
	# Eliminando conexao dos apelidos
	apelidos.pop(conexao, None)
	
	for key, valor in canais.items():
		if conexao in valor:
			valor.remove(conexao)	
	
	print(conexao, 'IRC: conexão fechada')
	conexao.fechar()


def dados_recebidos(conexao, dados):
	cont_linhas = 0
	print('IRC: recebeu dados de tamanho:', len(dados))
	if dados == b'': #caso nao possua dados, finalizar conexao
		return sair(conexao)
       	
	for i in range(len(dados)): # Conta quantidade de linhas com base no \n
		if dados[i] == 10: # 10, valor ascii do newline '\n'
			cont_linhas = cont_linhas + 1 
	
	d = b'\n'
	mensagens = dados.split(d) # Separa linhas em uma lista
	
	
	if b'' in mensagens:
		mensagens.remove(b'') # Limpeza de string vazias na lista

	
	for i in range(cont_linhas): # Voltando o \n apos o split
		mensagens[i] = mensagens[i] + d	

	for mensagem in mensagens: #para cada linha recebida
		if mensagem[-1] == 10: #Verifica se acabou a linha
			msg = conexao.dados_residuais + mensagem #Une mensagens incompletas para formar uma completa
			conexao.dados_residuais = b''
			msg_cortada = msg.split(b' ')
			funcao = msg_cortada[0]
			print('funcao', funcao)
			print('msg', msg)
			if funcao ==  b'PING':
				string = msg_cortada[1]
				for i in range(2, len(msg_cortada)):
					string = string + (b' %s' % msg_cortada[i])
				conexao.enviar(b':server PONG server :' + string)
				
			elif funcao == b'NICK':
				tratamento_nick(conexao,msg_cortada)
						
			elif funcao == b'PRIVMSG':
				tratamento_privmsg(conexao, msg_cortada, msg)
						
			elif funcao == b'JOIN':
				tratamento_join(conexao, msg_cortada)
			
			elif funcao == b'PART':
				tratamento_part(conexao, msg_cortada)
											
		else:
			conexao.dados_residuais = conexao.dados_residuais + mensagem

def tratamento_nick(conexao, msg_cortada): #Passo 4
	apelido_enviado = msg_cortada[1].rstrip(b'\r\n')
	nome = apelido_enviado.lower()

	if validar_nome(nome): #Se o nome for valido

		if nome in apelidos.values(): #Se o apelido ja existe
			if conexao in apelidos.keys(): #Pega o apelido atual
				apelido_antigo = apelidos[conexao]
			else: # se for o primeiro nick do usuario
				apelido_antigo = b'*'
			conexao.enviar(b':server 433 %s %s :Nickname is already in use\r\n' % (apelido_antigo, apelido_enviado))
						
		else:
			if conexao in apelidos.keys(): #Se o usuario estiver mudando o apelido
				conexao.enviar(b':%s NICK %s\r\n' % (apelidos[conexao], nome))
				apelidos[conexao] = nome
						
			else: #Se for o primeiro apelido do usuario
				apelidos[conexao] = nome
				conexao.enviar(b':server 001 %s :Welcome\r\n' % nome) #envia mensagem de sucesso
				conexao.enviar(b':server 422 %s :MOTD File is missing\r\n' % nome)

	else: # envia mensagem para o caso de que não for conectado corretamente
		conexao.enviar(b':server 432 * %s :Erroneous nickname\r\n' % nome)

def tratamento_privmsg(conexao, msg_cortada, msg):
	destinatario_apelido = msg_cortada[1].lower()
	conteudo = msg_cortada[2]
	for i in range(3, len(msg_cortada)):
			conteudo = conteudo + (b' %s' % msg_cortada[i])
	#Se for mensagem para grupo
	if destinatario_apelido[0] == 35: # 35 = '#'
		
					
		for key, valor in canais.items(): #Envia para todos que estao no canal
			if key == destinatario_apelido: 
				for destinatario in valor:
					if destinatario != conexao:
						destinatario.enviar(b':%s PRIVMSG %s %s' % (apelidos[conexao], key, conteudo))
									
	else: # Se for mensagem individual
		if destinatario_apelido in apelidos.values():
						
			for key, valor in apelidos.items():
				if valor == destinatario_apelido:
					destinatario = key
					break
						
			destinatario.enviar(b':%s PRIVMSG %s %s' % (apelidos[conexao], apelidos[destinatario], conteudo))

def tratamento_join(conexao, msg_cortada):
	canal = msg_cortada[1].lower()
				
	#Procura o nome do canal na mensagem
	if canal.endswith(b'\r\n'):
		nome_canal_limpo = canal[1:-2]
		nome_canal = canal[:-2]
	elif canal.endswith(b'\n'):
		nome_canal_limpo = canal[1:-1]
		nome_canal = canal[:-1]
	else:
		nome_canal_limpo = canal[1:]
		nome_canal = canal
				
	if (canal[0] == 35) and (validar_nome(nome_canal_limpo)): #Verifica se é um nome de canal valido
		
		# Se o canal ja existir
		if nome_canal in canais.keys():				
			canais[nome_canal].append(conexao) 
			for key, value in canais.items():
				if key == nome_canal:
					for destinatario in value:
						destinatario.enviar(b':%s JOIN :%s\r\n' % (apelidos[conexao], nome_canal))
									
		# Se o canal ainda nao existir
		else:
			# Cria uma lista vazia e insere
			canais[nome_canal] = []
			canais[nome_canal].append(conexao)
			conexao.enviar(b':%s JOIN :%s\r\n' % (apelidos[conexao], nome_canal))
					
		lista_conexoes = canais[nome_canal]
					
		lista_apelido = []
		# Criando lista de nicks que estao no canal para enviar no server 353
		for conex in lista_conexoes:
			if apelidos[conex] not in lista_apelido:	
				lista_apelido.append(apelidos[conex])
					

		lista_apelido_sorted = converttostr(sorted(lista_apelido), ' ')

		print(apelidos[conexao])
		print(lista_apelido)
		print(b':server 353 %s = %s :%s\r\n' % (apelidos[conexao], nome_canal, lista_apelido_sorted))
		conexao.enviar(b':server 353 %s = %s :%s\r\n' % (apelidos[conexao], nome_canal, lista_apelido_sorted))
					
					
		conexao.enviar(b':server 366 %s %s :End of /NAMES list.\r\n' % (apelidos[conexao], nome_canal))
					
					
	else: #Caso a validacao falhe
		conexao.enviar(b':server 403 %s :No such channel.\r\n' % canal[:-2])
					    
def tratamento_part(conexao, msg_cortada):
	canal = msg_cortada[1].lower().rstrip(b'\r\n')
				
	if canal in canais.keys():			
		for key, valor in canais.items():
			if key == canal:
				for destinatario in valor:	
					if destinatario == conexao:
						destinatario.enviar(b':%s PART %s\r\n' % (apelidos[conexao], canal))
						canais[key].remove(destinatario)
						break
				for destinatario in valor:
					destinatario.enviar(b':%s PART %s\r\n' % (apelidos[conexao], canal))


def conexao_aceita(conexao):
    print(conexao, 'nova conexão')
    conexao.dados_residuais = b''
    conexao.registrar_recebedor(dados_recebidos)

