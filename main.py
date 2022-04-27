from argparse import ArgumentParser
from ipaddress import (ip_interface, ip_network, ip_address)
from database import mushilogger
from goap import goap
import copy
import sys
import subprocess
import csv
import os
import datetime
import time
from pyfiglet import Figlet


def goap_write(arg, count):
  if count == 0:
    with open('./goap_contents.csv', 'w') as f:
      w = csv.writer(f)
      w.writerow(arg)
  else:
    with open('./goap_contents.csv', 'a') as f:
      w = csv.writer(f)
      w.writerow(arg)


def get_execute_time():
  dt_now = datetime.datetime.now()
  return str(dt_now.strftime("%Y-%m-%d %H:%M:%S"))


def check_ipaddr(args, mlogger):
  print("Check target IP address")
  mlogger.writelog("Check target IP address", "info")
  try:
    ip = ip_address(args)
    print(args + " is IP address")
    mlogger.writelog(args + " (target) is IP address.", "info")
  except:
    print(args + " is not IP address.")
    mlogger.writelog(args + " (target) is not IP address.", "error")
    exit(0)


def check_exclusion_ipaddr(args, mlogger):
  print("Check exclusion IP address")
  mlogger.writelog("Check exclusion IP address", "info")
  for row in args:
    try:
      if "/" in row:
        ip = ip_network(row)
        print(row + " (exclusion) is network address")
      else:
        ip = ip_address(row)
        print(row + " (exclusion) is IP address")
    except:
      print(row + " is not IP address or not network address.")
      mlogger.writelog(row + " is not IP address or not network address.", "error")
      exit(0)

def get_mushikago_ipaddr(neti):
  try:
    ipaddr = subprocess.check_output('ifconfig ' + neti + ' | grep "inet " | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
    netmask = subprocess.check_output('ifconfig ' + neti + ' | grep "inet " | grep -oP \'netmask [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/netmask //\'', shell=True).decode('utf-8')
    #print(res)
    return ipaddr.replace('\n', ''), netmask.replace('\n', '')
  except:
    print("get-ipaddr error!!")
    exit(0)


if __name__ == '__main__':
  node_id = 0
  record_id = 0
  pre_exe = None
  end_specify_ipaddr = 0
  mlogger = mushilogger.MushiLogger()
  home_dir = "/home/mushikago/src/mushikago-femto-official"

  parser = ArgumentParser()
  
  parser.add_argument('-ip', '--ipaddr', help='Set the IP address.')
  parser.add_argument('-exc', '--exclusion', help='Set exclusion IP addresses.', nargs='*')
  parser.add_argument('-t', '--type', default='eth0', help='Set the network interface type which eth0 or wlan0. The default is eth0. The eth0 is ethernet port on MUSHIKAGO. The wlan0 is wireless module on MUSHIKAGO. Other virtual network devices (such as tun0) can also be selected.')
  parser.add_argument('-a', '--action', choices=['it', 'ot'], default='it', help='Set the action file. The default is it. The it is targeting to IT system. The ot is targeting to OT system.')
  parser.add_argument('-ext', '--executiontime', help='Set the execution time. At execution time, the pentest is terminated. Please specify in minutes.')
  parser.add_argument('-exp', '--exploit', help='Turn on the exploit fuction. If you do not want to affect the system in any way, we recommend turning it off.')

  args = parser.parse_args()
  target_ip = "All Devices"
  exclusion_ip = "Nothing"
  execution_time = 0

  #aa_pattern = []

  f1 = Figlet(font="slant")
  f2 = Figlet(font="colossal")
  msg1 = f1.renderText("mushikago")
  msg2 = f2.renderText("FEMTO")
  time.sleep(1)
  print(msg1)
  print(" ---------- v1.0.10 ---------- ")
  time.sleep(1.5)
  print(msg2)

  print("Start of MUSHIKAGO penetration testing...")
  mlogger.writelog("Start of MUSHIKAGO penetration testing...", "info")

  print("Argument: {}".format(sys.argv))
  mlogger.writelog("Argument: " + str(sys.argv), "info")

  if args.ipaddr:
    target_ip = args.ipaddr
    check_ipaddr(args.ipaddr, mlogger)

  if args.exclusion:
    exclusion_ip = args.exclusion
    check_exclusion_ipaddr(args.exclusion, mlogger)

  if args.action == "it":
    actionfile = home_dir + '/goap/actions-it.json'
    mlogger.writelog("MUSHIKAGO IT mode", "info")
  elif args.action == "ot":
    actionfile = home_dir + '/goap/actions-ot.json'
    mlogger.writelog("MUSHIKAGO OT mode", "info")

  if args.executiontime:
    execution_time = int(args.executiontime)*60
    #execution_time = int(args.executiontime)
    start_time2 = time.time()
   
  goap_node = goap.GoapSymbol(actionfile)
  count = 0

  subprocess.run(home_dir + '/bat/msfrpc.sh', shell=True)
  time.sleep(20)

  while not (goap_node.state["GoalSymbol_AttackIcs"] == goap_node.goal["GoalSymbol_AttackIcs"] or goap_node.state["GoalSymbol_GetLocalSecretInfo"] == goap_node.goal["GoalSymbol_GetLocalSecretInfo"] or goap_node.state["GoalSymbol_GetNwSecretInfo"] == goap_node.goal["GoalSymbol_GetNwSecretInfo"]):

    #print("count = {}".format(count))

    if args.executiontime:
      current_time = time.time()
      elapsed_time = current_time - start_time2
      if elapsed_time > execution_time:
        print("{} minites have elapsed".format(args.executiontime))
        mlogger.writelog(args.executiontime + " minites have elapsed", "info")
        break

    # first time
    if count == 0: 
      plan = ["arpscan", "tcpscan"] 
      #plan = ["arpscan"] # test
      target, netmask = get_mushikago_ipaddr(args.type) 
      mushikago_ipaddr = target
      node_num = 0
      if args.ipaddr:
        target = args.ipaddr
        node_num = 1

    else: # After the second time
      target, node_num, target_state = goap_node.select_target(args.exclusion)

      print("target = {}".format(target))

      #if count == 1: # test plan
      while target == None:
        print("There is no target...")
        mlogger.writelog("There is no target...", "info")

        if args.ipaddr:
          end_specify_ipaddr = 1
          break

        g_content = ["No target", "network_scan"]
        goap_write(g_content, count)

        node_id = goap_node.network_scan(node_id, goap_node, mushikago_ipaddr)
        #node_id = goap_node.network_scan(node_id, goap_node, "192.168.1.1") # test
        target, node_num, target_state = goap_node.select_target(args.exclusion)

        #if target == None: # test
        #  break
        if target != None: # live code
          break

      if end_specify_ipaddr == 1:
        break

      goap_node.state = copy.deepcopy(target_state)

      print("main state = {}".format(goap_node.state))

      plan = goap_node.goap_plannning(goap_node)

      goap_node.state = copy.deepcopy(target_state)

    print("target = {}".format(target))
    mlogger.writelog("target = " + target, "info")

    if len(plan) > 0:
      g_content = copy.deepcopy(plan)
      g_content.insert(0, target)
      goap_write(g_content, count)

      node_id, record_id, pre_exe = goap_node.execute_plan(goap_node, node_id, plan, target, node_num, mushikago_ipaddr, args.type, args.ipaddr)
    else:
      goap_node.setting_non_target(goap_node, target, node_num)

    print("node_id = {}".format(node_id))

    count += 1

  print("MUSHIKAGO penetration testing complete...")
  mlogger.writelog("MUSHIKAGO penetration testing complete...", "info")
  #completion_time = get_execute_time()
