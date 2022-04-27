from database import mushilogger
from pymetasploit3.msfrpc import MsfRpcClient
import subprocess
import re
from arsenal import mynmap
from arsenal import msploit

class NetworkScan():

  def __init__(self):
    print("init NetworkScan..")

    self.mlogger = mushilogger.MushiLogger()
    self.exploit = msploit.MetaSploit()

    self.home_dir = "/home/mushikago/src/mushikago-femto-official"


  def msf_connection(self):
    client = MsfRpcClient('mushikago', port=55553)
    time.sleep(10)
    return client


  def drop_data(self, ipaddr, node, link):
    for num in range(1, len(node)): 
      print(node[num]["id"])
      if ipaddr == node[num]["id"]:
        del node[num]
        break

    for num in range(0, len(link)): 
      if ipaddr == link[num]["target"]:
        del link[num]
        break


  def execute_nwscan(self, nwaddr, src_ip, node, node_num, link, node_id, specify_ipaddr, addr_type):
    print('execute network segment scan...')
    self.mlogger.writelog("execute network scan...", "info")

    pattern = '(.*)(:)(.*)'

    try:
      if specify_ipaddr == True and addr_type == 0:
        ipaddr_list = []
        scan_addr = nwaddr
        self.mlogger.writelog("scan address = " + scan_addr, "info")
        res = subprocess.check_output('/usr/bin/proxychains4 /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr, shell=True).decode('utf-8')
        #res = subprocess.check_output(' /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr, shell=True).decode('utf-8')

        rows = re.split('\n', res)
        for row in rows:
          if ":[" in row:
            #print(row)
            result = re.match(pattern, row)
            ipaddr_list.append(result.group(1))

        if len(ipaddr_list) > 0:
          print("{} is probably runnning.".format(scan_addr))
          self.mlogger.writelog(scan_addr + " is probably running.", "info")
          #ipaddr_list.append(scan_addr)
        else:
          print("{} is probably down.".format(scan_addr))
          self.mlogger.writelog(scan_addr + " is probably down.", "info")

      #elif (specify_ipaddr == False and addr_type == 10) or (specify_ipaddr == False and addr_type == 172):
      elif specify_ipaddr == False and addr_type != 0:
        self.mlogger.writelog("scan address = " + nwaddr, "info")
        if node[node_num]["os"] == "Windows":
          ipaddr_list = self.exploit.execute_segmentscan_fm_win(node_num, node, nwaddr+"/16")
        elif node[node_num]["os"] == "Linux":
          ipaddr_list = self.exploit.execute_segmentscan_fm_linux(node_num, node, nwaddr)

        if len(ipaddr_list) > 0:
          print("{} is probably runnning.".format(nwaddr))
          self.mlogger.writelog(nwaddr + " is probably running.", "info")
          #self.exploit.setting_route("10.2.0.0", "255.255.0.0", node[node_num]["session"]) # test
          self.exploit.setting_route(nwaddr, "255.255.0.0", node[node_num]["session"])
        else:
          print("{} is probably down.".format(nwaddr))
          self.mlogger.writelog(nwaddr + " is probably down.", "info")

      print("IP address list = {}\n".format(ipaddr_list))
      self.mlogger.writelog("IP address list =  " + ','.join(ipaddr_list), "info")

      if len(ipaddr_list) == 0:
        return node_id

      check_iplist = []
      for ipaddr in ipaddr_list:
        for num in range(1, len(node)): 
          if ipaddr == node[num]["id"]:
            print("{} is checked. remove..".format(ipaddr))
            check_iplist.append(ipaddr)

      for ipaddr in check_iplist:
        ipaddr_list.remove(ipaddr)

      # add nodes
      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['record_id'] = self.next_record_id + (node_id + count)
        d['start_time'] = self.start_time
        d['id'] = ipaddr
        d['mac'] = ""
        d['vendor'] = ""
        d['group'] = node_id
        d['ports'] = []
        d['os'] = "Unknown"
        d['os_version'] = "Unknown"
        d['node_id'] = node_id + count
        d['src_ip'] = src_ip
        d['session'] = ""
        d['ics_protocol'] = {}
        d['ics_device'] = 0
        d['pwned_user'] = []
        d['secret_data'] = []
        d['no_action_target'] = 0
        d['goap'] = {
          "Symbol_GetLanNodes": None,
          "Symbol_TcpScan": True,
          "Symbol_IdentOs": True,
          "Symbol_InfoCollect": None,
          "Symbol_VulnScan": None,
          "Symbol_LateralMovement": None,
          "Symbol_GetNetworkInfo": None,
          "Symbol_DCCheck": None,
          "Symbol_LogonUserInfo": None,
          "Symbol_DomainUser": None,
          "Symbol_LocalUser": None,
          "Symbol_ValidUser": None,
          "Symbol_CreateUser": None,
          "Symbol_GetOsPatch": None,
          "Symbol_PrivilegeEscalation": None,
          "Symbol_ProcessInfo": None,
          "Symbol_ProcessMigrate": None,
          "Symbol_MainDriveInfo": None,
          "Symbol_SearchMainDrive": None,
          "Symbol_NwDriveInfo": None,
          "Symbol_SearchNwDrive": None,
          "GoalSymbol_GetLocalSecretInfo": None,
          "GoalSymbol_GetNwSecretInfo": None,
          "Symbol_PacketInfo": None,
          "Symbol_GetIcsProtocol": None,
          "Symbol_GetIcsDevice": None,
          "GoalSymbol_AttackIcs": None
        }
        d['logon_user'] = ""
        d['local_account_list'] = []
        d['local_account_pass'] = []
        d['local_account_hash'] = []
        d['domain_account_list'] = []
        d['domain_account_pass'] = []
        d['domain_account_hash'] = []
        d['dc_ipaddr'] = ""
        d['ad_domain'] = ""
        d['nbname'] = ""
        d['process_list'] = []
        d['security_process'] = []
        d['ipconfig_info'] = []
        d['netstat_info'] = []
        d['network_drive'] = []
        d['local_drive'] = []
        d['pcap_list'] = []
        d['os_patches'] = []
        d['openport_vuln_list'] = []
        d['local_vuln_list'] = []
        d['success_exploit'] = []
        d['success_local_exploit'] = []
        d['trial_exploits'] = []
        d['trial_local_exploits'] = []
        d['scan_ipaddr'] = []
        d['anti_virus'] = []
        d['edr'] = []
        d['firewall'] = []
        d['ids_ips'] = []
        d['utm'] = []
        d['waf'] = []
        d['siem'] = []
        d['ssl_inspection'] = []
        d['vpn'] = []
        d['ssp'] = []
        node.append(d)
        count = count + 1

      # add links
      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['target'] = ipaddr
        d['source'] = src_ip
        d['node_id'] = node_id + count
        d['value'] = 1
        link.append(d)
        count = count + 1

      if len(ipaddr_list) > 0:
        mynmapInstance = mynmap.MyNmap()
        proxy = 0
        for ipaddr in ipaddr_list:
          result = mynmapInstance.execute_nmap2(ipaddr, node, node_id, proxy)
          if result == -1:
            self.drop_data(ipaddr, node, link)
          else:
            node_id = node_id + 1

      #node_id = node_id + count
      print("node_id = {}".format(node_id))
      
      return node_id

    except Exception as e:
      print("nwscan error!!")
      self.mlogger.writelog("nwscan error!!", "error")
      print("contents of error = {}".format(e))


  def execute_nwscan2(self, nwaddr, src_ip, node, link, node_id, specify_ipaddr, addr_type):
    print('execute network scan...')
    self.mlogger.writelog("execute network scan...", "info")

    ipaddr_list = []
    pattern = '(.*)(:)(.*)'

    try:
      if specify_ipaddr == True and addr_type == 0:
        scan_addr = nwaddr
        self.mlogger.writelog("scan address = " + scan_addr, "info")
        #res = subprocess.check_output('/usr/bin/proxychains4 /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr, shell=True).decode('utf-8')
        res = subprocess.check_output('/usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr, shell=True).decode('utf-8')

        rows = re.split('\n', res)
        for row in rows:
          if ":[" in row:
            #print(row)
            result = re.match(pattern, row)
            ipaddr_list.append(result.group(1))

        if len(ipaddr_list) > 0:
          print("{} is probably runnning.".format(scan_addr))
          self.mlogger.writelog(scan_addr + " is probably running.", "info")
          #ipaddr_list.append(scan_addr)
        else:
          print("{} is probably down.".format(scan_addr))
          self.mlogger.writelog(scan_addr + " is probably down.", "info")

      elif specify_ipaddr == False and addr_type == 10:
        nwaddr = nwaddr.split('.')
        for i in range(0, 256):
        #for i in range(180, 220): # test
          scan_addr = nwaddr[0] + "." + nwaddr[1] + "." + str(i) + "."
          self.mlogger.writelog("scan address = " + scan_addr + "0", "info")
          #res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} /usr/bin/proxychains4 /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')
          res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')

          rows = re.split('\n', res)
          for row in rows:
            if ":[" in row:
              #print(row)
              result = re.match(pattern, row)
              ipaddr_list.append(result.group(1))

          if len(ipaddr_list) > 0:
            print("{}0 is probably runnning.".format(scan_addr))
            self.mlogger.writelog(scan_addr + "0 is probably running.", "info")
            break
          else:
            print("{}0 is probably down.".format(scan_addr))
            self.mlogger.writelog(scan_addr + "0 is probably down.", "info")

      elif specify_ipaddr == False and addr_type == 172:
        nwaddr = nwaddr.split('.')
        for i in range(0, 256):
          scan_addr = nwaddr[0] + "." + nwaddr[1] + "." + str(i) + "."
          self.mlogger.writelog("scan address = " + scan_addr + "0", "info")
          #res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} /usr/bin/proxychains4 /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')
          res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')

          rows = re.split('\n', res)
          for row in rows:
            if ":[" in row:
              #print(row)
              result = re.match(pattern, row)
              ipaddr_list.append(result.group(1))

          if len(ipaddr_list) > 0:
            print("{}0 is probably runnning.".format(scan_addr))
            self.mlogger.writelog(scan_addr + "0 is probably running.", "info")
            break
          else:
            print("{}0 is probably down.".format(scan_addr))
            self.mlogger.writelog(scan_addr + "0 is probably down.", "info")

      elif specify_ipaddr == False and addr_type == 192:
        nwaddr = nwaddr.split('.')
        scan_addr = nwaddr[0] + "." + nwaddr[1] + "." + nwaddr[2] + "."
        self.mlogger.writelog("scan address = " + scan_addr + "0", "info")
        #res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} /usr/bin/proxychains4 /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')
        res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')

        rows = re.split('\n', res)
        for row in rows:
          if ":[" in row:
            #print(row)
            result = re.match(pattern, row)
            ipaddr_list.append(result.group(1))

        if len(ipaddr_list) > 0:
          print("{}0 is probably runnning.".format(scan_addr))
          self.mlogger.writelog(scan_addr + "0 is probably running.", "info")
        else:
          print("{}0 is probably down.".format(scan_addr))
          self.mlogger.writelog(scan_addr + "0 is probably down.", "info")

      ipaddr_list = list(set(ipaddr_list))
      #port_list = list(set(port_list))

      print("IP address list = {}\n".format(ipaddr_list))
      self.mlogger.writelog("IP address list =  " + ','.join(ipaddr_list), "info")

      if len(ipaddr_list) == 0:
        print("testtest") # test
        return node_id

      check_iplist = []
      for ipaddr in ipaddr_list:
        for num in range(0, len(node)): 
          if ipaddr == node[num]["id"]:
            print("{} is checked. remove..".format(ipaddr))
            check_iplist.append(ipaddr)

      for ipaddr in check_iplist:
        ipaddr_list.remove(ipaddr)

      # add nodes
      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['record_id'] = self.next_record_id + (node_id + count)
        d['start_time'] = self.start_time
        d['id'] = ipaddr
        d['mac'] = ""
        d['vendor'] = ""
        d['group'] = node_id
        d['ports'] = []
        d['os'] = "Unknown"
        d['os_version'] = "Unknown"
        d['node_id'] = node_id + count
        d['src_ip'] = src_ip
        d['session'] = ""
        d['ics_protocol'] = {}
        d['ics_device'] = 0
        d['pwned_user'] = []
        d['secret_data'] = []
        d['no_action_target'] = 0
        d['goap'] = {
          "Symbol_GetLanNodes": None,
          "Symbol_TcpScan": True,
          "Symbol_IdentOs": True,
          "Symbol_InfoCollect": None,
          "Symbol_VulnScan": None,
          "Symbol_LateralMovement": None,
          "Symbol_GetNetworkInfo": None,
          "Symbol_DCCheck": None,
          "Symbol_LogonUserInfo": None,
          "Symbol_DomainUser": None,
          "Symbol_LocalUser": None,
          "Symbol_ValidUser": None,
          "Symbol_CreateUser": None,
          "Symbol_GetOsPatch": None,
          "Symbol_PrivilegeEscalation": None,
          "Symbol_ProcessInfo": None,
          "Symbol_ProcessMigrate": None,
          "Symbol_MainDriveInfo": None,
          "Symbol_SearchMainDrive": None,
          "Symbol_NwDriveInfo": None,
          "Symbol_SearchNwDrive": None,
          "GoalSymbol_GetLocalSecretInfo": None,
          "GoalSymbol_GetNwSecretInfo": None,
          "Symbol_PacketInfo": None,
          "Symbol_GetIcsProtocol": None,
          "Symbol_GetIcsDevice": None,
          "GoalSymbol_AttackIcs": None
        }
        d['logon_user'] = ""
        d['local_account_list'] = []
        d['local_account_pass'] = []
        d['local_account_hash'] = []
        d['domain_account_list'] = []
        d['domain_account_pass'] = []
        d['domain_account_hash'] = []
        d['dc_ipaddr'] = ""
        d['ad_domain'] = ""
        d['nbname'] = ""
        d['process_list'] = []
        d['security_process'] = []
        d['ipconfig_info'] = []
        d['netstat_info'] = []
        d['network_drive'] = []
        d['local_drive'] = []
        d['pcap_list'] = []
        d['os_patches'] = []
        d['openport_vuln_list'] = []
        d['local_vuln_list'] = []
        d['success_exploit'] = []
        d['success_local_exploit'] = []
        d['trial_exploits'] = []
        d['trial_local_exploits'] = []
        d['scan_ipaddr'] = []
        d['anti_virus'] = []
        d['edr'] = []
        d['firewall'] = []
        d['ids_ips'] = []
        d['utm'] = []
        d['waf'] = []
        d['siem'] = []
        d['ssl_inspection'] = []
        d['vpn'] = []
        d['ssp'] = []
        node.append(d)
        count = count + 1

      # add links
      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['target'] = ipaddr
        d['source'] = src_ip
        d['node_id'] = node_id + count
        d['value'] = 1
        link.append(d)
        count = count + 1

      if len(ipaddr_list) > 0:
        mynmapInstance = mynmap.MyNmap()
        proxy = 0
        for ipaddr in ipaddr_list:
          result = mynmapInstance.execute_nmap2(ipaddr, node, node_id, proxy)
          if result == -1:
            self.drop_data(ipaddr, node, link)
          else:
            node_id = node_id + 1

      #node_id = node_id + count
      print("node_id = {}".format(node_id))
      
      #ipaddr_list.clear()
      #port_list.clear()

      return node_id

    except Exception as e:
      print("nwscan2 error!!")
      self.mlogger.writelog("nwscan2 error!!", "error")
      print("contents of error = {}".format(e))


  def execute_nwscan4dc(self, scan_addr, src_ip, node, link, node_id):
    print('execute network scan for DC...')
    self.mlogger.writelog("execute network scan for DC...", "info")

    ipaddr_list = []

    try:
      self.mlogger.writelog("scan address = " + scan_addr, "info")
      res = subprocess.check_output('/usr/bin/proxychains4 /usr/bin/python3 ' + self.home_dir + '/arsenal/pscanner2.py ' + scan_addr, shell=True).decode('utf-8')
      rows = res.replace('\n', '').replace('[', '').replace(']', '').replace(' ', '')
      rows = re.split(',', rows)

      if len(rows) > 1:
        print("{} is probably runnning.".format(scan_addr))
        self.mlogger.writelog(scan_addr + " is probably running.", "info")
        ipaddr_list.append(scan_addr)
      else:
        print("{} is probably down.".format(scan_addr))
        self.mlogger.writelog(scan_addr + " is probably down.", "info")

      ipaddr_list = list(set(ipaddr_list))
      #port_list = list(set(port_list))

      print("IP address list = {}\n".format(ipaddr_list))
      self.mlogger.writelog("IP address list =  " + ','.join(ipaddr_list), "info")
      #print("port list = {}\n".format(port_list))

      check_iplist = []
      for ipaddr in ipaddr_list:
        for num in range(0, len(node)): 
          if ipaddr == node[num]["id"]:
            print("{} is checked. remove..".format(ipaddr))
            check_iplist.append(ipaddr)

      for ipaddr in check_iplist:
        ipaddr_list.remove(ipaddr)

      # add nodes
      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['record_id'] = self.next_record_id + (node_id + count)
        d['start_time'] = self.start_time
        d['id'] = ipaddr
        d['mac'] = ""
        d['vendor'] = ""
        d['group'] = node_id
        d['ports'] = []
        d['os'] = "Unknown"
        d['os_version'] = "Unknown"
        d['node_id'] = node_id + count
        d['src_ip'] = src_ip
        d['session'] = ""
        d['ics_protocol'] = {}
        d['ics_device'] = 0
        d['pwned_user'] = []
        d['secret_data'] = []
        d['no_action_target'] = 0
        d['goap'] = {
          "Symbol_GetLanNodes": None,
          "Symbol_TcpScan": True,
          "Symbol_UdpScan": None,
          "Symbol_IdentOs": True,
          "Symbol_InfoCollect": None,
          "Symbol_VulnScan": None,
          "Symbol_LateralMovement": None,
          "Symbol_GetNetworkInfo": None,
          "Symbol_DCCheck": None,
          "Symbol_LogonUserInfo": None,
          "Symbol_DomainUser": None,
          "Symbol_LocalUser": None,
          "Symbol_ValidUser": None,
          "Symbol_CreateUser": None,
          "Symbol_GetOsPatch": None,
          "Symbol_PrivilegeEscalation": None,
          "Symbol_ProcessInfo": None,
          "Symbol_ProcessMigrate": None,
          "Symbol_MainDriveInfo": None,
          "Symbol_SearchMainDrive": None,
          "Symbol_NwDriveInfo": None,
          "Symbol_SearchNwDrive": None,
          "GoalSymbol_GetLocalSecretInfo": None,
          "GoalSymbol_GetNwSecretInfo": None,
          "Symbol_PacketInfo": None,
          "Symbol_GetIcsProtocol": None,
          "Symbol_GetIcsDevice": None,
          "GoalSymbol_AttackIcs": None
        }
        d['logon_user'] = ""
        d['local_account_list'] = []
        d['local_account_pass'] = []
        d['local_account_hash'] = []
        d['domain_account_list'] = []
        d['domain_account_pass'] = []
        d['domain_account_hash'] = []
        d['dc_ipaddr'] = ""
        d['ad_domain'] = ""
        d['nbname'] = ""
        d['process_list'] = []
        d['security_process'] = []
        d['ipconfig_info'] = []
        d['netstat_info'] = []
        d['network_drive'] = []
        d['local_drive'] = []
        d['pcap_list'] = []
        d['os_patches'] = []
        d['openport_vuln_list'] = []
        d['local_vuln_list'] = []
        d['success_exploit'] = []
        d['success_local_exploit'] = []
        d['trial_exploits'] = []
        d['trial_local_exploits'] = []
        d['scan_ipaddr'] = []
        d['anti_virus'] = []
        d['edr'] = []
        d['firewall'] = []
        d['ids_ips'] = []
        d['utm'] = []
        d['waf'] = []
        d['siem'] = []
        d['ssl_inspection'] = []
        d['vpn'] = []
        d['ssp'] = []
        node.append(d)
        count = count + 1

      # add links
      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['target'] = ipaddr
        d['source'] = src_ip
        d['node_id'] = node_id + count
        d['value'] = 1
        link.append(d)
        count = count + 1

      if len(ipaddr_list) > 0:
        mynmapInstance = mynmap.MyNmap()
        proxy = 1
        for ipaddr in ipaddr_list:
          mynmapInstance.execute_nmap2(ipaddr, node, node_id, proxy)
          if result == -1:
            self.drop_data(ipaddr, node, link)
          else:
            node_id = node_id + 1

      #node_id = node_id + count
      print("node_id = {}".format(node_id))
      
      #ipaddr_list.clear()
      #port_list.clear()

      return node_id

    except Exception as e:
      print("nwscan error = {}".format(e))
      self.mlogger.writelog("nwscan error = " + e, "error")
