import socket
from handler import ServerHandler
import time

HOST = 'localhost'
PORT = 1232

try:
  server_handler = ServerHandler(HOST, PORT)
  #server_handler.daemon =True
  server_handler.start()
  #server_handler.join()
  while True:
    time.sleep(100)
    


except (KeyboardInterrupt, SystemExit):
  print('')
  print('Encerrando o servidor...')
  server_handler.stop()
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))


print('Hasta la vista baby!')