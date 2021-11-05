from database import mushilogger
import socket
import threading
import sys

class FastScan():
  def __init__(self):
    print("init NetworkScan..")

    self.mlogger = mushilogger.MushiLogger()

  def execute_fastscan(self, ipaddr):
  
    #scan_range = [1, 1024]
    #scan_port = [21,22,23,25,53,80,88,110,123,135,139,143,389,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,5985,8080]
    scan_port = [22,80,88,135,139,389,443,445,3389]
    
    threads = []
    ports = []
    #isopen = []
    
    def Run(port, i):
      try:
        con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return_code = con.connect_ex((ipaddr, port))
        con.close()
    
        if return_code == 0:
          #isopen[i] = 1
          ports.append(port)
      except:
        pass
    
    
    count = 0
    #for port in range(scan_range[0], scan_range[1]):
    for port in scan_port:
      #ports.append(port)
      #isopen.append(0)
      thread = threading.Thread(target=Run, args=(port, count))
      thread.start()
      threads.append(thread)
      count = count + 1
    
    #for i in range(len(threads)):
    #  threads[i].join()
    #  if isopen[i] == 1:
    #    print("%d open" % ports[i])
    
    for t in threads:
      t.join()
    
    #print("open port = {}".format(ports))
    print(ports)
