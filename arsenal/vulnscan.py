from database import mushilogger
import subprocess
import re
import copy
import pprint

class VulnScan():
  def __init__(self):
    print("init VulnScan")

    self.mlogger = mushilogger.MushiLogger()


  def execute_vulnscan(self, ip_addr, node_num, node, proxy):
    openport_vuln_list = []
    pattern = '(.*)(CVE:)(.*)'
  
    #print('\nexecute vulnscan to {}...'.format(ip_addr))
    self.mlogger.writelog("execute vulnscan to " + ip_addr, "info")

    check_port = []

    for port_num in range(0, len(node[node_num]["ports"])):
      check_port.append(node[node_num]["ports"][port_num]["number"].replace('/tcp', '').replace('/udp', ''))

    check_port = ",".join(check_port) 
    #print("check_port = {}".format(check_port))
  
    # --script vuln
    if proxy == 0:
      #res = subprocess.check_output('nmap -sTV --script vuln -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      res = subprocess.check_output('nmap -sTV -Pn --script vuln -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
    else:
      #res = subprocess.check_output('proxychains4 nmap -sTV --script vuln -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      res = subprocess.check_output('proxychains4 nmap -sTV -Pn --script vuln -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')

    rows = re.split('\n', res)

    for row in rows:
      if "IDs:" in row:
        cve_info = re.match(pattern, row)
        #print(cve_info.group(3).replace('\n', ''))
        openport_vuln_list.append(cve_info.group(3).replace('\n', ''))


    # --script vulners
    #res = subprocess.check_output('nmap -sTV --script vulners -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
    res = subprocess.check_output('nmap -sTV -Pn --script vulners -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
    
    rows = re.split('\n', res)
    
    pattern = '(.*)(https:)(.*)(CVE-)(.*)'
    pattern2 = '(.*)(/.*)' 
    
    for row in rows:
      try:
        if "https://vulners.com" in row and "CVE" in row:
          cve_info = re.match(pattern, row)
          if "/" in cve_info.group(5):
            cve_number = re.match(pattern2, cve_info.group(5))
            #print(cve_info.group(4) + cve_number.group(1))
            openport_vuln_list.append(cve_info.group(4) + cve_number.group(1))
          else:
            #print(cve_info.group(4) + cve_info.group(5).replace('\n', ''))
            openport_vuln_list.append(cve_info.group(4) + cve_info.group(5).replace('\n', ''))
      except:
        pass
    
    openport_vuln_list = list(dict.fromkeys(openport_vuln_list))

    self.mlogger.writelog("openport_vuln_list =  " + pprint.pformat(openport_vuln_list), "info")
    
    node[node_num]["openport_vuln_list"] = copy.deepcopy(openport_vuln_list)

    openport_vuln_list.clear()
