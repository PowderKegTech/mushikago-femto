import threading
from queue import Queue
import time
import socket
import sys
  
print_lock = threading.Lock()

if (len(sys.argv) != 2):
  print("Usage: # python3 pscanner2.py <ipaddress>")
  exit(0)

#scan_port = [21,22,25,53,80,88,135,139,389,443,445,3389]
scan_port = [21,22,23,25,53,80,88,110,123,135,139,143,389,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,5985,8010,8080]
open_port = []
  
# ip = socket.gethostbyname(target)
target = sys.argv[1]
  
def portscan(port):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    con = s.connect((target, port))
    with print_lock:
      #print('port is open', port)
      open_port.append(port)
    con.close()
  except:
    #print('port is close', port)
    pass
  
def threader():
  while True:
    worker = q.get()
    portscan(worker)
    q.task_done()
  
q = Queue()
  
#for x in range(4):
for x in range(10):
  t = threading.Thread(target=threader)
  t.daemon = True
  t.start()
  
start = time.time()
  
#for worker in range(1, 65535):
for worker in scan_port:
  q.put(worker)
  
q.join()

if open_port:
  print("{}:{}".format(target, open_port))
