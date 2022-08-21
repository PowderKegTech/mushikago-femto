from database import mushilogger
import subprocess
import copy
import pprint
import csv
import os

class IcsDetect():
  def __init__(self):
    print("init ICS Detect..")

    self.mlogger = mushilogger.MushiLogger()
    self.home_dir = os.getcwd()

  def detect_protocol(self, node_num, node):
    p_list = {}
    p_list.clear()

    #print('analyze pcap file for detect ics protocol...')
    self.mlogger.writelog("analyze pcap file for detect ics protocol...", "info")

    for pcap in node[node_num]["pcap_list"]:

      with open(self.home_dir + '/arsenal/ics_protocol_list.txt') as f:
        reader = csv.reader(f)
        for row in reader:
          protocol = row[0]
          protocol_name = row[1]

          try: 
            #res = subprocess.check_output('tshark -r ' + pcap + ' | grep -i \" ' + protocol + ' \"', shell=True).decode('utf-8')
            res = subprocess.check_output('/usr/bin/tshark -r ' + pcap + ' \"' + protocol + '\"', shell=True).decode('utf-8')
            print(res)
            self.mlogger.writelog(res, "info")

            rows = res.splitlines()
            for row in rows:
              c = row.split()
              #p_list[c[4]] = protocol_name
              p_list[c[2]] = protocol_name

          except:
            print("tshark error!!")
            self.mlogger.writelog("tshark error!!", "error")

    node[node_num]["ics_protocol"] = copy.deepcopy(p_list)

    for connect_ip, protocol in p_list.items():
      print("protocol = {}, connect_ip = {}".format(protocol, connect_ip))


  def detect_device(self, node_num, node):
    with open(self.home_dir + '/arsenal/ics_vendor_list.txt') as f:
      for vendor in f:
        vendor = vendor.replace('\n', '')
        if vendor.lower() in node[node_num]["vendor"].lower():
          print("ics vendor = {}".format(vendor))
          node[node_num]["ics_device"] = 1
          break


  def detect_alldevice(self, node):
    with open(self.home_dir + '/arsenal/ics_vendor_list.txt') as f:
      for vendor in f:
        vendor = vendor.replace('\n', '')
        for node_num in range(1, len(node)):
          if vendor.lower() in node[node_num]["vendor"].lower():
            print("ics vendor = {}".format(vendor))
            node[node_num]["ics_device"] = 1
