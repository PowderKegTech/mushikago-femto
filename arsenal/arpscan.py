from database import mushilogger
from mac_vendor_lookup import MacLookup
import subprocess
import re
from goap import goap

class ArpScan():

  def __init__(self):
    print("init ArpScan..")

    self.start_time = ""
    self.next_record_id = 0
    self.mlogger = mushilogger.MushiLogger()


  #def execute_arpscan(self, node, link, node_id, mushikago_ipaddr, nettype):
  def execute_arpscan(self, node, link, node_id, mushikago_ipaddr, nettype, specify_addr):
    print('execute arpscan...')
    self.mlogger.writelog("execute arpscan...", "info")

    try:
      if specify_addr:
        res = subprocess.check_output('arp-scan -x -N -r 1 -g -I ' + nettype + " " + specify_addr, shell=True).decode('utf-8')
      else:
        res = subprocess.check_output('arp-scan -l -x -N -r 1 -g -I ' + nettype, shell=True).decode('utf-8')
      print(res)
      self.mlogger.writelog("arpscan result = \n" + res, "info")
    except:
      print("arp-scan error!!")
      self.mlogger.writelog("arpscan error", "error")

    iplist = re.split('\t|\n', res)
    iplist.pop(-1)
    #print(iplist)
    if len(iplist) == 0:
      self.mlogger.writelog("No devices in this LAN", "info")
      node_id = self.noexecute_arpscan(node, link, node_id, mushikago_ipaddr, nettype, specify_addr)
      return node_id

    keys = ['id', 'mac', 'vendor']

    if (node_id == 0):
      d = {}
      d['record_id'] = self.next_record_id
      d['start_time'] = self.start_time
      d['id'] = mushikago_ipaddr
      #d['mac'] = "80:25:c2:f0:24:48"
      d['mac'] = self.get_macaddr(nettype)
      d['vendor'] = "Powder Keg Technologies"
      d['group'] = node_id
      d['ports'] = []
      d['os'] = "MUSHIKAGO OS"
      d['os_version'] = '1.0'
      d['node_id'] = 0
      d['src_ip'] = ""
      d['session'] = ""
      d['ics_protocol'] = {}
      d['ics_device'] = 0
      d['pwned_user'] = []
      d['secret_data'] = []
      d['no_action_target'] = 0
      d['goap'] = {
        "Symbol_GetLanNodes": True,
        "Symbol_TcpScan": None,
        "Symbol_IdentOs": None,
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

    for num in range(0, len(iplist), 3):
      d = dict(zip(keys, iplist[num:num+3]))
      d['record_id'] = self.next_record_id + (num//3 + 1 + node_id)
      d['start_time'] = self.start_time
      d['group'] = node_id
      d['ports'] = []
      d['os'] = 'Unknown'
      d['os_version'] = 'Unknown'
      d['node_id'] = num//3 + 1 + node_id
      d['src_ip'] = mushikago_ipaddr
      d['session'] = ""
      d['ics_protocol'] = {}
      d['ics_device'] = 0
      d['pwned_user'] = []
      d['secret_data'] = []
      d['no_action_target'] = 0
      d['goap'] = {
        "Symbol_GetLanNodes": True,
        "Symbol_TcpScan": None,
        "Symbol_IdentOs": None,
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
      #node["node"+str(node_num)] = d
      node.append(d)

    # create link
    keys = ['target']

    for num in range(0, len(iplist), 3):
      d = dict(zip(keys, iplist[num:num+1]))
      d['source'] = mushikago_ipaddr
      d['node_id'] = num//3 + 1 + node_id
      d['value'] = 1
      #node["node"+str(node_num)] = d
      link.append(d)

    node_id = num//3 + 1 + node_id
    return node_id

    #print(node)
    #print(link)
    #return node


  def noexecute_arpscan(self, node, link, node_id, mushikago_ipaddr, nettype, specify_addr):
    print('No execute arpscan to target...')
    self.mlogger.writelog("No execute arpscan to target...", "info")

    d = {}
    d['record_id'] = self.next_record_id
    d['start_time'] = self.start_time
    d['id'] = mushikago_ipaddr
    #d['mac'] = "80:25:c2:f0:24:48"
    d['mac'] = self.get_macaddr(nettype)
    d['vendor'] = "Powder Keg Technologies"
    d['group'] = node_id
    d['ports'] = []
    d['os'] = "MUSHIKAGO OS"
    d['os_version'] = '1.0'
    d['node_id'] = 0
    d['src_ip'] = ""
    d['session'] = ""
    d['ics_protocol'] = {}
    d['ics_device'] = 0
    d['pwned_user'] = []
    d['secret_data'] = []
    d['no_action_target'] = 0
    d['goap'] = {
      "Symbol_GetLanNodes": True,
      "Symbol_TcpScan": None,
      "Symbol_IdentOs": None,
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

    d = {}
    d['record_id'] = self.next_record_id + 1
    d['start_time'] = self.start_time
    d['id'] = specify_addr
    d['mac'] = ""
    d['vendor'] = "Unknown"
    d['group'] = node_id
    d['ports'] = []
    d['os'] = "Unknown"
    d['os_version'] = 'Unknown'
    d['node_id'] = 1
    d['src_ip'] = mushikago_ipaddr
    d['session'] = ""
    d['ics_protocol'] = {}
    d['ics_device'] = 0
    d['pwned_user'] = []
    d['secret_data'] = []
    d['no_action_target'] = 0
    d['goap'] = {
      "Symbol_GetLanNodes": True,
      "Symbol_TcpScan": None,
      "Symbol_IdentOs": None,
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

    node_id = 1

    # create link
    keys = ['target']

    d = {}
    d['target'] = specify_addr
    d['source'] = mushikago_ipaddr
    d['node_id'] = 1
    d['value'] = 1
    link.append(d)

    return node_id


  def execute_arpscan_fm_mp(self, node, link, node_id, src_ip):
    print('loading arp-scan.log...')
    self.mlogger.writelog("loading arp-scan.log...", "info")

    try:
      res = subprocess.check_output('awk \'BEGIN {OFS="\t"}{print($5, $3)}\' ./arp-scan.log', shell=True).decode('utf-8')
      #print(res)
      self.mlogger.writelog("arpscan result = \n" + res, "info")
    except:
      print("arp-scan file error!!")
      self.mlogger.writelog("arpscan fm mp error", "error")
      return node_id

    mac = MacLookup()
    #mac.update_vendors() # Update in a year
    
    iplist = re.split('\t|\n', res)
    iplist.pop(-1)
    #print(iplist)
    
    maclist = []

    if len(iplist) == 0:
      print("No exist devices from arpscan...")
      self.mlogger.writelog("No exist devices from arpscan...", "info")
      return node_id
    
    for num in range(1, len(iplist), 2):
      #print(iplist[num])
      try:
        maclist.append(mac.lookup(iplist[num]))
      except:
        maclist.append("Unknown")
     
    #print(maclist)
    
    keys = ['id', 'mac']

    decrement_count = 0

    print("len(iplist) = {}".format(len(iplist)))
    
    for num in range(0, len(iplist), 2):
      d = dict(zip(keys, iplist[num:num+2]))
      already_scanned = 0

      for node_num in range(0, len(node), 1):
        if node[node_num]["id"] == d["id"]:
          node[node_num]["vendor"] = maclist.pop(0)
          node[node_num]["mac"] = d["mac"]
          already_scanned = 1
          decrement_count += 1
          break

      print("ipaddr = {}".format(d["id"]))
      print("decrement_count = {}".format(decrement_count))
      
      if already_scanned == 0:
        d['record_id'] = self.next_record_id + (num//2 + node_id - decrement_count)
        d['start_time'] = self.start_time
        d['vendor'] = maclist.pop(0)
        d['group'] = node_id
        d['ports'] = []
        d['os'] = 'Unknown'
        d['os_version'] = 'Unknown'
        d['node_id'] = num//2 + node_id - decrement_count
        #d['node_id'] = (num//2 + 1 + node_id) - decrement_count
        d['src_ip'] = src_ip
        d['session'] = ""
        d['ics_protocol'] = {}
        d['ics_device'] = 0
        d['pwned_user'] = []
        d['secret_data'] = []
        d['no_action_target'] = 0
        d['goap'] = {
          "Symbol_GetLanNodes": True,
          "Symbol_TcpScan": None,
          "Symbol_IdentOs": None,
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
    
    #print(node)

    keys = ['target']

    decrement_count = 0
    duplicate_count = 0

    for num in range(0, len(iplist), 2):
      d = dict(zip(keys, iplist[num:num+1]))
      already_scanned = 0

      # If it executed tcpscan before arpscan, this information does not add links
      for node_num in range(0, len(link), 1):
        if link[node_num]["target"] == d["target"]:
          already_scanned = 1
          duplicate_count += 1
          decrement_count += 1
          break

      print("link ipaddr = {}".format(d["target"]))
      print("link decrement_count = {}".format(decrement_count))

      if already_scanned == 0:
        d['source'] = src_ip
        d['node_id'] = num//2 + node_id - decrement_count
        #d['node_id'] = (num//2 + 1 + node_id) - decrement_count
        d['value'] = 1
        link.append(d)
    
    node_id = num//2 + 1 + node_id - duplicate_count
    print("arpscan node_id = {}".format(node_id)) # test
    return node_id
    #print(link)

  
  def get_ipaddr(self):
    try:
      res = subprocess.check_output('ifconfig | grep -A3 eth0 | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
      #print(res)
      return res.replace('\n', '')
    except:
      print("get-ipaddr error!!")
      self.mlogger.writelog("get-ipaddr error!!", "error")


  def get_macaddr(self, nettype):
    try:
      res = subprocess.check_output('ifconfig | grep -A3 '+ nettype + ' | grep -oP \'ether ..:..:..:..:..:..\' | sed \'s/ether //\'', shell=True).decode('utf-8')
      #print(res)
      return res.replace('\n', '')
    except:
      print("get-macaddr error!!")
      self.mlogger.writelog("get-macaddr error!!", "error")
