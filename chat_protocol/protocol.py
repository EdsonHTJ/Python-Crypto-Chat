from abc import ABC, abstractmethod
from myAES import en_AES, dec_AES

class ProtocolMessage(ABC):

  def __init__(self, msgType='', msgLength=0, msgValue=''):
    self.msgType = msgType
    self.msgLength = msgLength
    self.msgValue = msgValue

  def encode(self,key):
    return en_AES(f'{self.msgType} {self.msgValue}'.encode('utf8'),key)
    

  def decode(self, data,key):
    data = dec_AES(data,key)
    msg = data.decode('utf-8')

    self.msgType = msg[0:4]
    self.msgLength = len(data)
    self.msgValue = msg[5:]

  def __repr__(self):
    return f'{self.msgType} {self.msgValue}'

class UsernameRequest(ProtocolMessage):
  def __init__(self, username=''):
    ProtocolMessage.__init__(self, 'USER', 5 + len(username.encode('utf-8')), username)


class UsernameResponse(ProtocolMessage):
  def __init__(self, type='', message=''):
    ProtocolMessage.__init__(self, type.ljust(4), 5 + len(message.encode('utf-8')), message)


class PasswordRequest(ProtocolMessage):
  def __init__(self, password=''):
    ProtocolMessage.__init__(self, "PASS", 5 + len(password.encode('utf-8')), password)


class PasswordResponse(ProtocolMessage):
  def __init__(self, type='', message=''):
    ProtocolMessage.__init__(self, type.ljust(4), 5 + len(message.encode('utf-8')), message)


class MessageRequest(ProtocolMessage):
  def __init__(self, message=''):
    ProtocolMessage.__init__(self, "MESG", 5 + len(message.encode('utf-8')), message)

class MessageResponse(ProtocolMessage):
  def __init__(self, type='', message=''):
    ProtocolMessage.__init__(self, type.ljust(4), 5 + len(message.encode('utf-8')), message)

class closeCon(ProtocolMessage):
  def __init__(self, message='closing connection'):
    ProtocolMessage.__init__(self, "CLOS", 5 + len(message.encode('utf-8')), message)

class broadcast(ProtocolMessage):
  def __init__(self, username='' , message=''):
    msg = username + ': ' + message
    ProtocolMessage.__init__(self, 'BROD', 5 + len(msg.encode('utf-8')), msg)

class broadcastResponse(ProtocolMessage):
  def __init__(self, type='' , message='Recived'):
    ProtocolMessage.__init__(self, type.ljust(4), 5 + len(message.encode('utf-8')), message)

class PrivateMsgRequest(ProtocolMessage):
  def __init__(self,  username= '',message='',):
    msg = username + ': ' + message
    ProtocolMessage.__init__(self, 'PRIV', 5 + len(msg.encode('utf-8')), msg)

class PrivateMsgRequestToServer(ProtocolMessage):
  def __init__(self,  message=' '):
    ProtocolMessage.__init__(self, "PRIV", 5 + len(message.encode('utf-8')), message)

class PrivateResponse(ProtocolMessage):
  def __init__(self, type='' , message='Recived'):
    ProtocolMessage.__init__(self, type.ljust(4), 5 + len(message.encode('utf-8')), message)



class RetriveRequest(ProtocolMessage):
  def __init__(self, message='Request Users'):
    ProtocolMessage.__init__(self, "RETR", 5 + len(message.encode('utf-8')), message)

class RetriveResponse(ProtocolMessage):
  def __init__(self,type='OK' ,ParticipantsList=''):
    msg=' '
    for participant in ParticipantsList:
      msg=msg+str(participant)+','
    ProtocolMessage.__init__(self, type.ljust(4), 5 + len(msg.encode('utf-8')), msg)
  

