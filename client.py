import socket
import threading
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from myAES import en_AES,dec_AES, AESkeyGen
import chat_protocol.protocol as cp

HOST = 'localhost'
PORT = 1232


def interromper():
    raise Exception



def handle_received_message(sock,AESkey):
    while True:
        data = sock.recv(1024)
        #print(data.decode('utf-8'))
        if not data:
            pass

        else:
            #print(data)
            Pm =cp.ProtocolMessage()
            Pm.decode(data,AESkey)

            #print(Pm.msgType)
            if Pm.msgType == 'CLOS':
                print('O servidor Encerrou a conexão')
                interromper()
            elif Pm.msgType == 'BROD':
                print(Pm.msgValue)  
                sock.sendall(cp.broadcastResponse('OK').encode(AESkey)) 
            elif Pm.msgType == 'PRIV':
                print('Priv Message From '+Pm.msgValue) 
            elif Pm.msgType.strip() == 'ERR':
                print('Erro '+Pm.msgValue)
            elif Pm.msgType.strip() == 'OK':
                print('OK '+Pm.msgValue) 

        

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # 1 - Criar par de chaves pública e privada
    Keys = RSA.generate(2048)

    pk  = Keys.publickey()
    pkexp = pk.exportKey()
    privkexp = Keys.exportKey()

    # 2 - Enviar a chave publica para o servidor
    s.sendall(pkexp)


    # 3 - Receber a chave publica do servidor
    ServerPK = s.recv(1024)
    ServerPkObj = RSA.import_key(ServerPK)

    
    # 4 - Gerar uma chave assimétrica aleatória

    AESkey = AESkeyGen()
    print("Chave AES GERADA:")
    print(AESkey)
    encryptor = PKCS1_OAEP.new(ServerPkObj)
    decryptor = PKCS1_OAEP.new(Keys)
    EnAESkey = encryptor.encrypt(AESkey)
    # 5 - Enviar a chave simétrica para o servidor de forma 
    ServerOK=0
    while ServerOK==0:

        s.sendall(EnAESkey)


        AESKeyVerifyEncrypt = s.recv(1024)
        AESKeyVerify = decryptor.decrypt(AESKeyVerifyEncrypt)

        if(AESKeyVerify == AESkey):

            s.sendall("OK".encode('utf-8'))
            print("OK")
            ServerOK=1
        else:
            s.sendall("ERR".encode('utf-8'))

        


    print("Aeskey: ",end='')
    print(AESkey)
    #     criptografada usando a chave publica do servidor


    # Envia a mensagem USER
    username = input('Digite seu nome de usuário: ')
    s.sendall(cp.UsernameRequest(username).encode(AESkey))

    data = s.recv(1024)
    username_response = cp.UsernameResponse()
    username_response.decode(data,AESkey)
    print(username_response.msgType.strip())
    if username_response.msgType.strip() == 'ERR':
        print("Erro:" + str(username_response.msgValue.strip()))
        exit()

    # Envia a mensagem PASS
    password = input('Digite a senha de acesso ao chat: ')
    s.sendall(cp.PasswordRequest(password).encode(AESkey))

    data = s.recv(1024)
    password_response = cp.PasswordResponse(data)
    password_response.decode(data,AESkey)
    if password_response.msgType.strip() == 'ERR':
        print("Erro:" + str(password_response.msgValue.strip()))
        exit()
    else:
        print(str(password_response.msgValue.strip()))

    t = threading.Thread(target=handle_received_message, args=(s,AESkey,))
    t.start()

    while True:
        try:
            msg = input()
            if(msg=='RETR'):
                s.sendall(cp.RetriveRequest().encode(AESkey))

            elif(msg[0:4]=='PRIV'):
                s.sendall(cp.PrivateMsgRequestToServer(msg[4:]).encode(AESkey))
            
            else:
                s.sendall(cp.MessageRequest(msg).encode(AESkey))
        except KeyboardInterrupt:
            print('')
            print('Encerrando o cliente...')
            s.sendall(cp.closeCon().encode(AESkey))
            s.close()
            break
        except Exception:
            print('')
            print('Encerrando o cliente...')
            s.sendall(cp.closeCon().encode(AESkey))
            s.close()
            break


print('Bye bye!')



 