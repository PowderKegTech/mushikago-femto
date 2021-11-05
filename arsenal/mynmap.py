from database import mushilogger
import subprocess
import re
import copy
import pprint

class MyNmap():
  def __init__(self):
    print("init MyNmap")

    self.mlogger = mushilogger.MushiLogger()


  def execute_nmap(self, ip_addr, num, node, proxy):
    detect_ports = []
    d = {}
    flag = 0
    windows_count = 0
    linux_count = 0
  
    print('\nexecute nmap to {}...'.format(ip_addr))
    self.mlogger.writelog("execute nmap to " + ip_addr, "info")
  
    check_port = '1-65535'
    #check_port = '1-200' # test

    try:
      if proxy == 0:
        #res = subprocess.check_output('nmap -sSV -O -Pn -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
        #res = subprocess.check_output('nmap -sTV -O -Pn -T4 -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
        res = subprocess.check_output('nmap -sTV -O -Pn -T5 -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
        #res = subprocess.check_output('nmap -sT -Pn -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      else:
        res = subprocess.check_output('proxychains4 nmap -sTV -O -Pn -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      rows = re.split('\n', res)
      #print(rows)

      for row in rows:
        #if 'MAC Address' in row:
        if '/tcp' not in row:
          flag = 0
        if flag == 1:
          row = row.replace('\n', '')
          row = re.sub(r'\s+', ' ', row)
          c = row.split(' ', 3)
          d["number"] = c[0]
          d["service"] = c[2]
          try: # check version
            if c[3]:
              d["version"] = c[3]
          except:
            d["version"] = ""
          detect_ports.append(copy.deepcopy(d))
        if 'SERVICE' and 'VERSION' in row:
          flag = 1
        if 'windows' in row.lower():
          windows_count = windows_count + 1
        if 'linux' in row.lower():
          linux_count = linux_count + 1

    except:
      print("No TCP port open!!")
      self.mlogger.writelog("No tcp port open!!", "error")


    #print("detect_ports = {}".format(detect_ports))
    #print("windows_count = {}".format(windows_count))
    #print("linux_count = {}".format(linux_count))
    self.mlogger.writelog("OS identify count = windows: " + str(windows_count) + ", linux: " + str(linux_count), "info")

    self.mlogger.writelog("detect_ports =  " + pprint.pformat(detect_ports), "info")

    # OS identify and version identify
    if(windows_count == 0 and linux_count == 0):
      node[num]["os"] = "Unknown"
    elif (windows_count > 0 and windows_count >= linux_count):
      node[num]["os"] = "Windows"
      # windows version detect
      for port_num in range(0, len(detect_ports)):
        if detect_ports[port_num]["number"] == "445/tcp":
          if "Microsoft Windows 7 - 10 microsoft-ds" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows 7"
          elif detect_ports[port_num]["version"] in "Windows Server 2008 R2 - 2012":
            node[num]["os_version"] = "Windows Server 2008"
          elif detect_ports[port_num]["version"] in "Windows Server 2016":
            node[num]["os_version"] = "Windows Server 2016"
          elif detect_ports[port_num]["version"] in "Windows Server 2012":
            node[num]["os_version"] = "Windows Server 2012"
          elif detect_ports[port_num]["version"] in "Windows Server 2003":
            node[num]["os_version"] = "Windows Server 2003"
          elif detect_ports[port_num]["version"] in "Windows XP":
            node[num]["os_version"] = "Windows XP"
          elif detect_ports[port_num]["version"] == "":
            node[num]["os_version"] = "Windows 10"
            
      # winserver detect
      if node[num]["os_version"] == "":
        for port_num in range(0, len(detect_ports)):
          if detect_ports[port_num]["number"] == "25/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "53/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "80/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "88/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "110/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "143/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "389/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "993/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "995/tcp":
            node[num]["os_version"] = "Windows Server"

    elif (windows_count < linux_count):
      node[num]["os"] = "Linux"
    
    node[num]["ports"] = copy.deepcopy(detect_ports)

    #node[num]["goap"]["Symbol_GetLanNodes"] = True
    node[num]["goap"]["Symbol_TcpScan"] = True
    node[num]["goap"]["Symbol_IdentOs"] = True

    detect_ports.clear()


  #def execute_mas2nmap(self, ip_addr, node, num, proxy, check_port):
  def execute_nmap2(self, ip_addr, node, num, proxy):
  #def execute_mas2nmap(self, ip_addr, proxy, check_port):
    detect_ports = []
    d = {}
    flag = 0
    windows_count = 0
    linux_count = 0
  
    print('\nexecute nmap to {}...'.format(ip_addr))
    self.mlogger.writelog("execute nmap to " + ip_addr, "info")
    print("deep masscan node_id = {}".format(num))
  
    #check_port = '1-65535'
    #check_port = '1-200'
    check_port = '21,22,23,25,53,80,88,110,123,135,139,143,389,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,5985,8080'

    try:
      if proxy == 0:
        res = subprocess.check_output('nmap -sTV -T5 -O -Pn --open -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      else:
        res = subprocess.check_output('proxychains4 nmap -sTV -T5 -Pn -O --open -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      rows = re.split('\n', res)
      print(rows)

      for row in rows:
        if '/tcp' not in row:
          flag = 0
        if flag == 1:
          row = row.replace('\n', '')
          row = re.sub(r'\s+', ' ', row)
          c = row.split(' ', 3)
          d["number"] = c[0]
          d["service"] = c[2]
          try: # check version
            if c[3]:
              d["version"] = c[3]
          except:
            d["version"] = ""
          detect_ports.append(copy.deepcopy(d))
        if 'SERVICE' and 'VERSION' in row:
          flag = 1
        if 'windows' in row.lower():
          windows_count = windows_count + 1
        if 'linux' in row.lower():
          linux_count = linux_count + 1

    except:
      print("No TCP port open!!")
      self.mlogger.writelog("No tcp port open!!", "error")

    #print("detect_ports = {}".format(detect_ports))
    #print("windows_count = {}".format(windows_count))
    #print("linux_count = {}".format(linux_count))
    self.mlogger.writelog("OS identify count = windows: " + str(windows_count) + ", linux: " + str(linux_count), "info")

    self.mlogger.writelog("detect_ports =  " + pprint.pformat(detect_ports), "info")

    if (windows_count >= linux_count):
      node[num]["os"] = "Windows"
    elif (windows_count < linux_count):
      node[num]["os"] = "Linux"
      # windows version detect
      for port_num in range(0, len(detect_ports)):
        if detect_ports[port_num]["number"] == "445/tcp":
          if "Microsoft Windows 7 - 10 microsoft-ds" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows 7"
          elif detect_ports[port_num]["version"] in "Windows Server 2008 R2 - 2012":
            node[num]["os_version"] = "Windows Server 2008"
          elif detect_ports[port_num]["version"] in "Windows Server 2016":
            node[num]["os_version"] = "Windows Server 2016"
          elif detect_ports[port_num]["version"] in "Windows Server 2012":
            node[num]["os_version"] = "Windows Server 2012"
          elif detect_ports[port_num]["version"] in "Windows Server 2003":
            node[num]["os_version"] = "Windows Server 2003"
          elif detect_ports[port_num]["version"] in "Windows XP":
            node[num]["os_version"] = "Windows XP"
          elif detect_ports[port_num]["version"] == "":
            node[num]["os_version"] = "Windows 10"
            
      # winserver detect
      if node[num]["os_version"] == "":
        for port_num in range(0, len(detect_ports)):
          if detect_ports[port_num]["number"] == "25/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "53/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "80/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "88/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "110/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "143/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "389/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "993/tcp":
            node[num]["os_version"] = "Windows Server"
          elif detect_ports[port_num]["number"] == "995/tcp":
            node[num]["os_version"] = "Windows Server"
    elif(windows_count == 0 and linux_count == 0):
      node[num]["os"] = "Unknown"
    
    node[num]["ports"] = copy.deepcopy(detect_ports)

    #node[num]["goap"]["Symbol_GetLanNodes"] = True
    node[num]["goap"]["Symbol_TcpScan"] = True
    node[num]["goap"]["Symbol_IdentOs"] = True

    detect_ports.clear()
