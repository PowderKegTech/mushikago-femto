from database import mushilogger
import subprocess
import re
from arsenal import mynmap

class NetworkScan():
  def __init__(self):
    print("init NetworkScan..")

    self.mlogger = mushilogger.MushiLogger()


  def execute_nwscan(self, nwaddr, src_ip, node, link, node_id, specify_ipaddr, addr_type):
    print('execute network scan...')
    self.mlogger.writelog("execute network scan...", "info")

    ipaddr_list = []
    check_port = '21,22,80,135,139,389,443,445'

    try:
      if specify_ipaddr == True and addr_type == 0:
        scan_addr = nwaddr
        self.mlogger.writelog("scan address = " + scan_addr, "info")
        res = subprocess.check_output('proxychains4 /usr/bin/python3 ./arsenal/pscanner2.py ' + scan_addr, shell=True).decode('utf-8')
        rows = res.replace('\n', '').replace('[', '').replace(']', '').replace(' ', '')
        rows = re.split(',', rows)

        if len(rows) > 1:
          print("{} is probably runnning.".format(scan_addr))
          self.mlogger.writelog(scan_addr + " is probably running.", "info")
          ipaddr_list.append(scan_addr)
        else:
          print("{} is probably down.".format(scan_addr))
          self.mlogger.writelog(scan_addr + " is probably down.", "info")

      elif specify_ipaddr == False and addr_type == 10:
        nwaddr = nwaddr.split('.')
        for i in range(0, 255):
          scan_addr = nwaddr[0] + "." + nwaddr[1] + "." + str(i) + "."
          self.mlogger.writelog("scan address = " + scan_addr + "0", "info")
          res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} proxychains4 /usr/bin/python3 ./arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')

          if ":" in res:
            rows = res.replace('\n', '').replace('[', '').replace(']', '').replace(' ', '')
            exist_ipaddr = re.split(':', rows)
            if len(exist_ipaddr[1]) > 1:
              print("{}0 is probably runnning.".format(scan_addr))
              self.mlogger.writelog(scan_addr + "0 is probably running.", "info")
              ipaddr_list.append(exist_ipaddr[0])
          else:
            print("{}0 is probably down.".format(scan_addr))
            self.mlogger.writelog(scan_addr + "0 is probably down.", "info")

          if len(ipaddr_list) > 0:
            break

      elif specify_ipaddr == False and addr_type == 172:
        nwaddr = nwaddr.split('.')
        for i in range(0, 255):
          scan_addr = nwaddr[0] + "." + nwaddr[1] + "." + str(i) + "."
          self.mlogger.writelog("scan address = " + scan_addr + "0", "info")
          res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} proxychains4 /usr/bin/python3 ./arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')

          if ":" in res:
            rows = res.replace('\n', '').replace('[', '').replace(']', '').replace(' ', '')
            exist_ipaddr = re.split(':', rows)
            if len(exist_ipaddr[1]) > 1:
              print("{}0 is probably runnning.".format(scan_addr))
              self.mlogger.writelog(scan_addr + "0 is probably running.", "info")
              ipaddr_list.append(exist_ipaddr[0])
          else:
            print("{}0 is probably down.".format(scan_addr))
            self.mlogger.writelog(scan_addr + "0 is probably down.", "info")

          if len(ipaddr_list) > 0:
            break

      elif specify_ipaddr == False and addr_type == 192:
        nwaddr = nwaddr.split('.')
        scan_addr = nwaddr[0] + "." + nwaddr[1] + "." + nwaddr[2] + "."
        self.mlogger.writelog("scan address = " + scan_addr + "0", "info")
        res = subprocess.check_output('seq 1 254 | xargs -P 50 -I{} proxychains4 /usr/bin/python3 ./arsenal/pscanner2.py ' + scan_addr + "{}", shell=True).decode('utf-8')
        if ":" in res:
          rows = res.replace('\n', '').replace('[', '').replace(']', '').replace(' ', '')
          exist_ipaddr = re.split(':', rows)

          if len(exist_ipaddr[1]) > 1:
            print("{}0 is probably runnning.".format(scan_addr))
            self.mlogger.writelog(scan_addr + "0 is probably running.", "info")
            ipaddr_list.append(exist_ipaddr[0])
        else:
          print("{}0 is probably down.".format(scan_addr))
          self.mlogger.writelog(scan_addr + "0 is probably down.", "info")

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
        d['id'] = ipaddr
        d['mac'] = ""
        d['vendor'] = ""
        d['group'] = node_id
        d['ports'] = []
        d['os'] = ""
        d['os_version'] = ''
        d['node_id'] = node_id + count
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
        proxy = 1
        for ipaddr in ipaddr_list:
          mynmapInstance = mynmap.MyNmap()
          mynmapInstance.execute_nmap2(ipaddr, node, node_id, proxy)

      node_id = node_id + count
      print("node_id = {}".format(node_id))
      
      ipaddr_list.clear()
      #port_list.clear()

      return node_id

    except:
      print("nwscan error!!")
      self.mlogger.writelog("nwscan error!!", "error")



  def execute_nwscan4dc(self, scan_addr, src_ip, node, link, node_id):
    print('execute network scan for DC...')
    self.mlogger.writelog("execute network scan for DC...", "info")

    ipaddr_list = []
    check_port = '21,22,80,135,139,389,443,445'
    #port_list = []

    try:
      self.mlogger.writelog("scan address = " + scan_addr, "info")
      res = subprocess.check_output('proxychains4 /usr/bin/python3 ./arsenal/pscanner.py ' + scan_addr, shell=True).decode('utf-8')
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
        d['id'] = ipaddr
        d['mac'] = ""
        d['vendor'] = ""
        d['group'] = node_id
        d['ports'] = []
        d['os'] = ""
        d['os_version'] = ''
        d['node_id'] = node_id + count
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
          #"Symbol_BruteForce": None,
          "Symbol_ArpPoisoning": None,
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
        proxy = 1
        for ipaddr in ipaddr_list:
          mynmapInstance = mynmap.MyNmap()
          mynmapInstance.execute_nmap2(ipaddr, node, node_id, proxy)

      node_id = node_id + count
      print("node_id = {}".format(node_id))
      
      ipaddr_list.clear()
      #port_list.clear()

      return node_id

    except:
      print("nwscan error!!")
      self.mlogger.writelog("nwscan error!!", "error")
