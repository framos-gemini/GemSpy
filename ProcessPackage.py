from dataclasses import dataclass, field
import datetime
import sys
import multiprocessing
import queue
from Code import Code
from DataClients import DataClients
import time
import threading

@dataclass
class ProcessPackage:
    q : multiprocessing.Queue
    dataClient : DataClients
    lock : threading.Lock
    code = Code()
    # TODO. There is a different conversion type between python 3.9.12 and 3.7.3
    # when try to get the cmd = int(l.get_field('command')). In 3.9.12 the int 
    # needs to specified the base, but in 3.7.3 when you specify the base, 
    # the result is differnt. For example, the command 0x15, specifying the base 16
    # the result is 33 instead of 21. The class of the l.get_filed is the pyshark.packet.fields.LayerFieldsContainer
    # command: 0x15 - 21, type:<class 'pyshark.packet.fields.LayerFieldsContainer'>, cmd-New: 33 cmd2: 21 
    CONVERT_3_7 = sys.version_info[:3] == (3,7,3) 
    nPack : int = 0
    nMax : int = 0
    bLoop : bool = False
    wLog : bool = False
    ###############################
    def setBreakLoop(self, opt):
       self.bLoop = opt
       print('setBreakLoop')

    ###############################
    def isHostAllow(self, lhost,  hsrc, hdst):
       if not lhost:
          return True
       for h in lhost:
          if hdst == h or hsrc == h:
             return True
       print(f'This host is going to be filter {hsrc} - {hdst}')
       return False  

    ###############################
    def analyzeLayers(self, p):
       try:
          printPackg=False
          for l in p:
             if (l.get_field('command')):
               cmd = int(l.get_field('command')) if self.CONVERT_3_7 else int(l.get_field("command"), 16)
               if (cmd == 0x0006): ## Search 
                  # Search Request ['command', 'size', 'doreply', 'version', 'cid', 'p2', 'pv']
                  if (l.get('doreply') is not None):
                     printPackg=True
                     #print(f'Search {p.ip.get("src_host")}, {p.udp.get("srcport")}, {l.get("pv")}, {l.get("cid")}')
                     self.dataClient.addCID(p.ip.get('src_host'), p.udp.get('srcport'), l.get("pv"), l.get("cid"))
                  else:
                     # Search response ['command', 'size', 'serv_port', 'serv_ip', 'cid', 'version']
                     # the upd.get('dstport') contains the port of the client which is used in the 
                     # self.dataClient structure created to store all information
                     self.dataClient.addDstHost(p.ip.get('dst_host'), p.ip.get('src_host'),l.get("serv_port"), l.get('cid'),p.udp.get('dstport'))
               elif (cmd == 0x0012): ## Create Channel 
                  #l.pretty_print()
                  sid = l.get('sid')
                  if (sid is None):
                     # Client fields ['command', 'size', 'cid', 'version', 'pv']
                     self.dataClient.addCID2(p.ip.get('src_host'), p.ip.get('dst_host'), p.tcp.get('dstport'), l.get('cid'), p.tcp.get('srcport'), l.get("pv"))
                  else:
                     # Sever fields ['command', 'size', 'dtype', 'count', 'cid', 'sid']
                     self.dataClient.addSID(p.ip.get('dst_host'), l.get('cid'), p.tcp.get('dstport'), l.get('sid'))
               elif (cmd == 0x0001): ## Event
                  if (l.get('mask')): ## It is a client
                     self.dataClient.addSubsId(p.ip.get('src_host'), l.get('sid'), p.tcp.get('srcport'), l.get('sub'))
                  else:  ## It is a server
                     self.dataClient.addValue(p.ip.get('dst_host'), l.get('sub'), p.tcp.get('dstport'), l.get("data_value"), f'{l.get("data_timestamp_sec")}.{l.get("data_timestamp_nsec")}')
               elif (cmd == 0x000f): # Read 
                  ecaCode = l.get('eca')
                  if (ecaCode is None): # Message from Client Read Request
                     self.dataClient.setOpeID(p.ip.get('src_host'), p.tcp.get('srcport'), l.get('sid'), l.get('ioid'))
                  else: # IOC 
                     ecaCode = int(ecaCode)
                     if (ecaCode == self.code.ECA_NORMAL): # Value transmitted well. 
                        self.dataClient.addValueByOid(p.ip.get('dst_host'), 
                                                  l.get('ioid'), 
                                                  p.tcp.get('dstport'),
                                                  l.get("data_value"), 
                                                  #datetime.fromtimestamp(p.sniff_timestamp).strftime("%m/%d/%Y_%H:%M:%S")) 
                                                  p.sniff_timestamp) 
                     else:
                        print(f'Error. Analysed the {ecaCode} code')
               elif (cmd == 0x0004): # Write Package. This package is only sent by user
                  self.dataClient.setWriteOrder(p.ip.get('src_host'), 
                                            l.get('sid'), 
                                            p.tcp.get('srcport'),
                                            l.get("data_value"), 
                                            #datetime.fromtimestamp(p.sniff_timestamp).strftime("%m/%d/%Y_%H:%M:%S"))
                                            p.sniff_timestamp)
                  if (l.get("data.value") == 'Close' or l.get("data.value") == 'Open'):
                      print(f'{p.ip.get("src_host")}-{l.get("sid")}-{p.tcp.get("srcport")}-{l.get("data_value")}')
               elif (cmd == 0x0014):
                  print(f'{p.ip.get("src_host")}, {l.get("str")}, {p.tcp.get("srcport")}')
                  self.dataClient.setUserName(p.ip.get('src_host'), l.get('str'), p.tcp.get('srcport'))
               elif (cmd == 0x0015):
                  self.dataClient.setHostName(p.ip.get('src_host'), l.get('str'), p.tcp.get('srcport'))
       except AttributeError as e1:
          print ('Errorrrrrrrrrrrrrrrrrrrrrrrrr')
          print(e1)
          p.pretty_print()
          print(self.dataClient)

    def printQueueSize(self):
       print('\n\n\n ########################################################################')
       print(f'nPackages: {self.nPack} -> queue-size: {self.q.qsize()} q-max: {self.nMax}')
  
    def writeLog(self):
       self.wLog = True

    ###############################
    def readPackgCon(self):
      while (not self.bLoop):
         self.nMax = self.q.qsize() if self.q.qsize()> self.nMax else self.nMax
         try:
            p = self.q.get(timeout=5)
         except queue.Empty:
            continue
         except Exception as e:
            print('Not analized')
            print(e)
            return 0
         self.nPack+=1
         if (len(p.get_multiple_layers('ca')) == 0):
             #print(f'Discard the package {self.nPack}')
             #p.pretty_print()
             continue
         self.lock.acquire()
         self.analyzeLayers(p)
         self.lock.release()
         
      print("Go out of the readPackgCon loop")      


