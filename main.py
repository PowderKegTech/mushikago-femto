from argparse import ArgumentParser
from database import mushilogger
from goap import goap
import copy
import sys
import subprocess
import csv
import os

def goap_write(arg, count):
  if count == 0:
    with open('goap_contents.csv', 'w') as f:
      w = csv.writer(f)
      w.writerow(arg)
  else:
    with open('goap_contents.csv', 'a') as f:
      w = csv.writer(f)
      w.writerow(arg)


def get_ipaddr(neti):
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
  mlogger = mushilogger.MushiLogger()

  print("Start of MUSHIKAGO penetration testing...")
  mlogger.writelog("Start of MUSHIKAGO penetration testing...", "info")

  parser = ArgumentParser()
  
  parser.add_argument('-ip', '--ipaddr', help='Set the IP address.')
  parser.add_argument('-t', '--type', default='eth0', help='Set the network interface type which eth0 or wlan0. The default is eth0. The eth0 is ethernet port on MUSHIKAGO. The wlan0 is wireless module on MUSHIKAGO. Other virtual network devices (such as tun0) can also be selected.')
  parser.add_argument('-a', '--action', choices=['it', 'ot'], default='it', help='Set the action file. The default is it. The it is targeting to IT system. The ot is targeting to OT system.')

  args = parser.parse_args()

  if args.action == "it":
    actionfile = './goap/actions-it.json'
  elif args.action == "ot":
    actionfile = './goap/actions-ot.json'
   
  goap_node = goap.GoapSymbol(actionfile)
  count = 0

  subprocess.run('./bat/msfrpc.sh', shell=True)

  while not (goap_node.state["GoalSymbol_AttackIcs"] == goap_node.goal["GoalSymbol_AttackIcs"] or goap_node.state["GoalSymbol_GetLocalSecretInfo"] == goap_node.goal["GoalSymbol_GetLocalSecretInfo"] or goap_node.state["GoalSymbol_GetNwSecretInfo"] == goap_node.goal["GoalSymbol_GetNwSecretInfo"]):

    #print("count = {}".format(count))

    # first time
    if count == 0: 
      plan = ["arpscan", "tcpscan"] 
      target, netmask = get_ipaddr(args.type) 
      mushikago_ipaddr = target
      node_num = 0

    else: # After the second time
      target, node_num, target_state = goap_node.select_target()

      print("target = {}".format(target))

      if count == 1: # test
      #if target == None:
        print("There is no target...")
        mlogger.writelog("There is no target...", "info")
        node_id = goap_node.network_scan(node_id, goap_node, mushikago_ipaddr)
        target, node_num, target_state = goap_node.select_target()

        if target == None:
          print("After all, there is no target...")
          mlogger.writelog("After all, there is no target...Terminate MUSHIKAGO", "info")
          exit(0)

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

      node_id = goap_node.execute_plan(goap_node, node_id, plan, target, node_num, mushikago_ipaddr, args.type, args.ipaddr)
    else:
      goap_node.setting_non_target(goap_node, target, node_num)

    print("node_id = {}".format(node_id))

    count += 1

  print("MUSHIKAGO penetration testing complete...")
  mlogger.writelog("Complete of MUSHIKAGO penetration testing...", "info")
