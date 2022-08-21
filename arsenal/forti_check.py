from database import mushilogger
import subprocess
import re
import os
import copy
import pprint

class FortiCheck():
  def __init__(self):
    print("init MyNmap")

    self.mlogger = mushilogger.MushiLogger()
    self.home_dir = os.getcwd()


  def forti_check(self, number, service, version):
    with open(self.home_dir + '/arsenal/ics_protocol_list.txt') as f:
    #with open('./arsenal/forti_check.txt') as f:
      for forti_port in f:
        if forti_port.replace('\n', '') == number:
          if "?" in service:
            if version == "":
              return 1, False
          elif "FortiGate" in version:
            return 5, False
          elif "http" == service:
            if version == "":
              return 1, False
            else:
              return 0, True
          else:
            return 0, True
    return 0, True


  def execute_nmap(self, ip_addr, num, node, proxy):
    detect_ports = []
    d = {}
    flag = 0
    forti_point = 0
    exist_flag = 0
  
    print('\nexecute forti_check to {}...'.format(ip_addr))
    self.mlogger.writelog("execute forti_check to " + ip_addr, "info")
  
    check_port = '1-65535'
    #check_port = '1-200' # test

    try:
      if proxy == 0:
        res = subprocess.check_output('nmap -sTV -O -Pn -T5 -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
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
            else:
              d["version"] = ""
          except:
            d["version"] = ""

          point, entity = self.forti_check(d["number"], d["service"], d["version"])
          forti_point += point

          if entity:
            exist_flag = 1
            detect_ports.append(copy.deepcopy(d))
          
        if 'SERVICE' and 'VERSION' in row:
          flag = 1
        if 'windows' in row.lower():
          os_judgement["windows"] = os_judgement["windows"] + 1
        if 'linux' in row.lower():
          os_judgement["linux"] = os_judgement["linux"] + 1
        if 'freebsd' in row.lower():
          os_judgement["freebsd"] = os_judgement["freebsd"] + 1
        if 'netbsd' in row.lower():
          os_judgement["netbsd"] = os_judgement["netbsd"] + 1
        if 'macos' in row.lower() or 'mac os' in row.lower():
          os_judgement["macos"] = os_judgement["macos"] + 1

    except:
      print("No TCP port open!!")
      self.mlogger.writelog("No tcp port open!!", "error")
      return 0

    print("forti_point = {}".format(forti_point))
    self.mlogger.writelog("forti_point = " + forti_point, "info")

    if forti_point > 3:
      print("FortiGate exists.")
      self.mlogger.writelog("FortiGate exists.", "info")
    else:
      print("FortiGate does not exist.")
      self.mlogger.writelog("FortiGate does not exist.", "info")

    if exist_flag == 1:
      print("This machine exists.")
      self.mlogger.writelog("This machine exists.", "info")
    else:
      print("This machine does not exist.")
      self.mlogger.writelog("This machine does not exist.", "info")
      return 0

    #print("detect_ports = {}".format(detect_ports))
    #self.mlogger.writelog("OS identify count = windows: " + str(windows_count) + ", linux: " + str(linux_count), "info")
    self.mlogger.writelog("detect_ports = " + pprint.pformat(detect_ports), "info")

    # OS identify and version identify
    if node[num]["os"] == "MUSHIKAGO OS":
      pass
    elif max(os_judgement.values()) == 0:
      node[num]["os"] = "Unknown"
    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "windows":
      node[num]["os"] = "Windows"
      # windows version detect
      for port_num in range(0, len(detect_ports)):
        if detect_ports[port_num]["number"] == "445/tcp":
          if "Microsoft Windows 7 - 10 microsoft-ds" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows 7"
          elif "Windows Server 2008 R2 - 2012" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows Server 2008"
          elif "Windows Server 2016" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows Server 2016"
          elif "Windows Server 2012" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows Server 2012"
          elif "Windows Server 2003" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows Server 2003"
          elif "Windows XP" in detect_ports[port_num]["version"]:
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

    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "linux":
      node[num]["os"] = "Linux"
      for port_num in range(0, len(detect_ports)):
        if "ubuntu" in detect_ports[port_num]["version"].lower():
          node[num]["os_version"] = "Ubuntu"
        if "centos" in detect_ports[port_num]["version"].lower():
          node[num]["os_version"] = "CentOS"
    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "freebsd":
      node[num]["os"] = "FreeBSD"
    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "netbsd":
      node[num]["os"] = "NetBSD"
    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "macos":
      node[num]["os"] = "MacOS"
    
    node[num]["ports"] = copy.deepcopy(detect_ports)

    node[num]["goap"]["Symbol_TcpScan"] = True
    node[num]["goap"]["Symbol_IdentOs"] = True

    detect_ports.clear()


  def execute_nmap2(self, ip_addr, node, num, proxy):
    detect_ports = []
    d = {}
    flag = 0
    os_judgement = {"windows":0, "linux":0, "freebsd":0, "netbsd":0, "macos":0}
  
    print('\nexecute nmap to {}...'.format(ip_addr))
    self.mlogger.writelog("execute nmap to " + ip_addr, "info")
  
    #check_port = '1-65535'
    check_port = '21,22,23,25,53,80,88,110,123,135,139,143,389,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,5985,8010,8080'
    #check_ics_port = '102,80,443,502,1089,1090,1091,4000,4840,20000,34962,34963,3496444818'

    try:
      if proxy == 0:
        res = subprocess.check_output('nmap -sTV -T5 -O -Pn --open -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      else:
        res = subprocess.check_output('proxychains4 nmap -sTV -T5 -Pn -O --open -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
        #res = subprocess.check_output('proxychains4 nmap -sTV -Pn -O --open -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
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
          os_judgement["windows"] = os_judgement["windows"] + 1
        if 'linux' in row.lower():
          os_judgement["linux"] = os_judgement["linux"] + 1
        if 'freebsd' in row.lower():
          os_judgement["freebsd"] = os_judgement["freebsd"] + 1
        if 'netbsd' in row.lower():
          os_judgement["netbsd"] = os_judgement["netbsd"] + 1
        if 'macos' in row.lower() or 'mac os' in row.lower():
          os_judgement["macos"] = os_judgement["macos"] + 1

    except:
      print("No TCP port open!!")
      self.mlogger.writelog("No tcp port open!!", "error")

    #print("detect_ports = {}".format(detect_ports))
    #self.mlogger.writelog("OS identify count = windows: " + str(windows_count) + ", linux: " + str(linux_count), "info")

    self.mlogger.writelog("detect_ports =  " + pprint.pformat(detect_ports), "info")

    # OS identify and version identify
    if max(os_judgement.values()) == 0:
      node[num]["os"] = "Unknown"
    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "windows":
      node[num]["os"] = "Windows"
      # windows version detect
      for port_num in range(0, len(detect_ports)):
        if detect_ports[port_num]["number"] == "445/tcp":
          if "Microsoft Windows 7 - 10 microsoft-ds" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows 7"
          elif "Windows Server 2008 R2 - 2012" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows Server 2008"
          elif "Windows Server 2016" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows Server 2016"
          elif "Windows Server 2012" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows Server 2012"
          elif "Windows Server 2003" in detect_ports[port_num]["version"]:
            node[num]["os_version"] = "Windows Server 2003"
          elif "Windows XP" in detect_ports[port_num]["version"]:
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

    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "linux":
      node[num]["os"] = "Linux"
      for port_num in range(0, len(detect_ports)):
        if "ubuntu" in detect_ports[port_num]["version"].lower():
          node[num]["os_version"] = "Ubuntu"
        if "centos" in detect_ports[port_num]["version"].lower():
          node[num]["os_version"] = "CentOS"
    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "freebsd":
      node[num]["os"] = "FreeBSD"
    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "netbsd":
      node[num]["os"] = "NetBSD"
    elif max(os_judgement.items(), key=lambda x:x[1])[0] == "macos":
      node[num]["os"] = "MacOS"
    
    node[num]["ports"] = copy.deepcopy(detect_ports)

    node[num]["goap"]["Symbol_TcpScan"] = True
    node[num]["goap"]["Symbol_IdentOs"] = True

    detect_ports.clear()
