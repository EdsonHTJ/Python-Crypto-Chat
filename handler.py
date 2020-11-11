import chat_protocol.protocol as cp
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from threading import Thread
from socket import socket, AF_INET, SOCK_STREAM

users = [
  {'username': 'profbrunolopes', 'password': 'unifor2020'},
  {'username': 'joao', 'password': 'admin123'},
  {'username': 'maria', 'password': 's3cr3t'},
  {'username': 'edson', 'password': '123123'},
  {'username': 'isagui', 'password': 'abcabc'}
  ]

class ServerHandler(Thread):

  def __init__(self, host, port):
    Thread.__init__(self)
    self.host = host
    self.port = port
    self.connections = []
    self.active = True
    self.Keys = RSA.generate(2048)

    self.ServerPublicKey  = self.Keys.publickey()
    self.Exportedpk = self.ServerPublicKey.exportKey()
    
    
  
  def run(self):
    with socket(AF_INET, SOCK_STREAM) as s:
      s.bind((self.host, self.port))
      s.listen(5)


      while self.active:
        print(f'Waiting for new connections...')

        conn, addr = s.accept()

        ch = ConnectionHandler(conn,addr, self)
        self.connections.append(ch)
        ch.start()
 
      # Adicionar o código solicitando o fechamento das conexões com os clientes!
        

  def notify_all_connections(self, msg, from_addr,fromusr):
    for client in self.connections:
      if(client.addr != from_addr):
        client.conn.sendall(cp.broadcast(fromusr,msg).encode(client.AesKey))

  def stop(self):
    for client in self.connections:
        client.conn.sendall(cp.closeCon().encode(client.AesKey))
        client.conn.close()
        
    self.active = False
    


class ConnectionHandler(Thread):

  def __init__(self, conn, addr, callback):
    Thread.__init__(self)
    self.conn = conn
    self.addr = addr
    self.callback = callback
    self.active = True
    self.username = ''
    self.password = ''
    self.ClientPk = ''
    self.ClientPkObj = {}

  def run(self):

    print(f'The client {self.addr} is connected!')
    print('')
    #if 1:
    try:
   
      self.ClientPk = self.conn.recv(1024)

      self.ClientPkObj = RSA.import_key(self.ClientPk)

      decryptor = PKCS1_OAEP.new(self.callback.Keys)
      encryptor = PKCS1_OAEP.new(self.ClientPkObj)
     
    


      self.conn.sendall(self.callback.Exportedpk)
      ClientOK=0
      while ClientOK==0:    
        EnAesKey = self.conn.recv(1024)
      
        self.AesKey = decryptor.decrypt(EnAesKey)

        print(f"Chave AES do cliente {self.addr} ",end='')
        print(self.AesKey)
        ServerEnAeskey  = encryptor.encrypt(bytes(self.AesKey))

        self.conn.sendall((ServerEnAeskey))
        
        data = self.conn.recv(1024)
        if data.decode('utf-8').strip()=="OK":
          ClientOK=1




      data = self.conn.recv(1024)
      
      username_request = cp.UsernameRequest()
      username_request.decode(data,self.AesKey)
      if username_request.msgType.strip() != 'USER':
        self.conn.sendall(cp.UsernameResponse('ERR', 'Usuario esperado. ').encode(self.AesKey))
        self.conn.sendall(cp.closeCon().encode(self.AesKey))
        self.conn.close()
      else :
        for i in self.callback.connections:
          if(i.username == username_request.msgValue ):
            self.conn.sendall(cp.UsernameResponse('ERR', 'usuario ja conectado.').encode(self.AesKey))
            self.conn.sendall(cp.closeCon().encode(self.AesKey))
            self.conn.close()
            break

        self.username = username_request.msgValue
        for i in range(len(users)):
          if users[i]['username'] == self.username:
            self.conn.sendall(cp.UsernameResponse('OK', 'Por favor envie a senha!').encode(self.AesKey))
            break
          elif (i == len(users)-1):
            self.conn.sendall(cp.UsernameResponse('ERR', 'Nome de usuário invalido.').encode(self.AesKey))
            self.conn.sendall(cp.closeCon().encode(self.AesKey))
            self.conn.close()
            break


      data = self.conn.recv(1024)
      password_request = cp.PasswordRequest()
      password_request.decode(data,self.AesKey)

      if password_request.msgType.strip() != 'PASS':
        self.conn.sendall(cp.UsernameResponse('ERR', 'Senha esperada. ').encode(self.AesKey))
        self.conn.sendall(cp.closeCon().encode(self.AesKey))
        self.conn.close()
      else:
        self.password = password_request.msgValue
        for i in range(len(users)):
          if users[i]['username'] == self.username and users[i]['password'] == self.password:
            self.conn.sendall(cp.PasswordResponse('Ok', 'Bem vindo ao servidor!').encode(self.AesKey))
            break
          elif i==len(users)-1:
            self.conn.sendall(cp.PasswordResponse('ERR', 'Senha invalida.').encode(self.AesKey))
            self.conn.sendall(cp.closeCon().encode(self.AesKey))
            self.conn.close()

      with self.conn:
        while self.active:
          
          data = self.conn.recv(1024)
          Pm =cp.ProtocolMessage()
          Pm.decode(data,self.AesKey) 
          print(Pm.msgType)

          if Pm.msgType == 'MESG':
            print("Entrou")
            mesg = cp.MessageRequest(Pm.msgValue.strip())

            if not data: break
            print(f'Received message from {self.addr}: {mesg.msgValue}')
            self.callback.notify_all_connections(mesg.msgValue, self.addr,self.username)

          elif Pm.msgType == 'RETR':
            participantes= []
            for conn in self.callback.connections:
               participantes.append(conn.username)
            mesg = cp.RetriveResponse('OK',participantes)
            mesg = mesg.encode(self.AesKey)
            #print(mesg)
            self.conn.sendall(mesg)
          elif Pm.msgType == 'PRIV':
            data = Pm.msgValue
            try:
              data = data.strip()
              pivot = data.index(' ')
              username = data[:pivot]
              msg = data[pivot:]
              print('Username:'+username+'   Mesg:'+msg)
              mesg = cp.PrivateMsgRequest(self.username,msg)
              print(f'Received Private message from {self.addr}: {mesg.msgValue}')
              if not data: break
              find = 0
              for connection in self.callback.connections:
                if connection.username == username:
                  connection.conn.sendall(mesg.encode(connection.AesKey))
                  find = 1
              if find==0:
                mesg = cp.PrivateResponse('ERR','Usuario Nao Conectado').encode(self.AesKey)
                self.conn.sendall(mesg)
              else:
                mesg = cp.PrivateResponse('OK','Mensagem Enviada').encode(self.AesKey)
                self.conn.sendall(mesg)
            except:
                mesg = cp.PrivateResponse('ERR','Mensagem invalida').encode(self.AesKey)
                self.conn.sendall(mesg)
              


          elif Pm.msgType == 'CLOS':
            #print('Cliente:'+str(self.addr)+'Desconectado')
            self.active = False
            self.callback.connections.remove(self)
            self.conn.close()
            break
          
    except:
      self.active = False
      self.callback.connections.remove(self)
      self.conn.close() 

    print(f'The client {self.addr} was disconected!')