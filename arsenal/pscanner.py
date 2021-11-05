import socket
import threading
import sys

if (len(sys.argv) != 2):
  print("Usage: # python3 pscanner.py <ipaddress>")
  exit(0)

print_lock = threading.Lock()

scan_port = [22,80,88,135,139,389,443,445]
host = sys.argv[1]

threads = []
ports = []

def Run(port, i):
  try:
    con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with print_lock:
      return_code = con.connect_ex((host, port))
    con.close()

    if return_code == 0:
      #isopen[i] = 1
      ports.append(port)
  except:
    pass


count = 0
for port in scan_port:
  #ports.append(port)
  #isopen.append(0)
  thread = threading.Thread(target=Run, args=(port, count))
  thread.start()
  threads.append(thread)
  count = count + 1

for t in threads:
  t.join()

print("{}".format(ports))
