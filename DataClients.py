from dataclasses import dataclass, field
from Code import Code
import json
import copy
import threading
import datetime

@dataclass
class DataClients:
   fpath: str
   lpvFilter : set = field(default_factory=set)
   lock: threading.Lock = None
   data: dict = field(default_factory=dict)

   ################################## 
   def filterHost(self, host):
       return re.sub(r'\.cl\.gemini\.edu','',host)
   ################################## 
   def setHostName(self, ipHost, hostname, srcPort):
      print (f'setHostname. {ipHost}-{hostname}-{srcPort} ')
      if not (ipHost in self.data and srcPort in self.data[ipHost]):
         self.addPort(ipHost, srcPort)
         print(self.data)
      self.data[ipHost][srcPort]['hostname'] = hostname

   ################################## 
   def setUserName(self, ipHost, user, srcPort):
      print (f'setUserName. {ipHost}-{user}-{srcPort} ')
      if not (ipHost in self.data and srcPort in self.data[ipHost]):
         self.addPort(ipHost, srcPort)
      self.data[ipHost][srcPort]['user'] = user
      #print(self.data)
   ################################## 
   def addHost(self, h):
      if self.data.get(h) is None:
         self.data[h] = {}
      return h
   ################################## 
   def addPort(self, h, srcPort):
      self.addHost(h)
      if not (srcPort in self.data[h]):
         self.data[h][srcPort] = {}
         return 1
      return 0
   ##################################
   def checkPvFilter(self, pvName):
      if (not self.lpvFilter) or  (pvName in  self.lpvFilter):
         return True
      return False
   ##################################
   def addCID(self, h, srcPort, pvName, cid):
      if not self.checkPvFilter(pvName):
         return False
      self.addPort(h, srcPort)
      if not (cid in self.data[h][srcPort]):
          self.data[h][srcPort][cid] = { 'val' : [], 'sid':'', 'pv':pvName, 'opId':set(), 'subsId':'', 'dstHost':'', 'dstPort':'', 'write' : []}
          return True
      return False
   ##################################
   def addDstHost(self, hsrc, dst_host, serv_port, cid, srcPort):
      if hsrc in self.data and srcPort in self.data[hsrc] and cid in self.data[hsrc][srcPort]:
         self.data[hsrc][srcPort][cid]['dstHost'] = dst_host
         self.data[hsrc][srcPort][cid]['dstPort'] = serv_port
         return True
      return False
   ##################################
   def addCID2(self, srcHost, dst_host, serv_port, cid, srcPort, pvName):
      if (self.addCID(srcHost, srcPort, pvName, cid)):
         self.data[srcHost][srcPort][cid]['dstHost'] = dst_host
         self.data[srcHost][srcPort][cid]['dstPort'] = serv_port
         return True
      return False
   ##################################
   def addSID(self, src_host, cid, srcPort, sid):
      if (src_host in self.data and srcPort in self.data[src_host] and cid in self.data[src_host][srcPort]):
         #print(f'{src_host}->{srcPort}->{cid}->{sid}')
         self.data[src_host][srcPort][cid]['sid'] = sid
         return True
      return False
   ##################################
   def getCidFromInField(self, src_host, val, inField, srcPort):
      if not (src_host in self.data and srcPort in self.data[src_host]):
         return None
      for cid in self.data[src_host][srcPort]:
         if (cid == 'user' or cid == 'hostname'):
            continue
         #print(f'Comparing {val} - {self.data[src_host][srcPort][cid][inField]} ')
         if (isinstance(self.data[src_host][srcPort][cid][inField], set)):
            if (val in self.data[src_host][srcPort][cid][inField]):
               return cid

         if (val == self.data[src_host][srcPort][cid][inField]):
            return cid
      return None
   ##################################
   def addSubsId(self, src_host, sid, srcPort, subsId):
      cid = self.getCidFromInField(src_host, sid, 'sid', srcPort)
      if (cid is not None):
         self.data[src_host][srcPort][cid]['subsId'] = subsId
   ##################################
   def addValue(self, src_host, subId, srcPort, val, ts):
      cid = self.getCidFromInField(src_host, subId, 'subsId', srcPort)
      if (cid is not None):
         self.data[src_host][srcPort][cid]['val'].append({ts:val})
   ##################################
   def addValueByOid(self, src_host, opId, srcPort, val, ts):
      cid = self.getCidFromInField(src_host, opId, 'opId', srcPort)
      if (cid is not None):
         self.data[src_host][srcPort][cid]['val'].append({ts:val})
         self.data[src_host][srcPort][cid]['opId'].discard(opId)
         return True
      #print(f'addValueByOid fail,{src_host}-{srcPort}-{opId}-{cid}->{ts}:{val}')
      return False

   ##################################
   # TODO. The operationId should be an array, because it could be more request before a notify request arrives
   def setOpeID(self, src_host, srcPort, sid, oid):
      cid = self.getCidFromInField(src_host, sid, 'sid', srcPort)
      if (cid is not None):
         self.data[src_host][srcPort][cid]['opId'].add(oid)
         return True
      return False
   ##################################
   def setWriteOrder(self, src_host, sid, srcPort, val, ts ):
      cid = self.getCidFromInField(src_host, sid, 'sid', srcPort)
      if (cid is not None):
          self.data[src_host][srcPort][cid]['write'].append({ts:val})

   def writeLog(self, path):
      if (path):
         self.lock.acquire()
         with open(path, "w") as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False, default=serialize_sets)
         self.lock.release()
   
   def tsKeyToTimestamp(self, obj):
     userOut = []
     #for el in self.data[h][port][cid]['val']:
     for el in obj:
        for k in el:
           try:
              userOut.append(f'{datetime.datetime.fromtimestamp(float(k))} -> {el[k]}')
           except:
              userOut.append(f'{el} -> el[k]')
              
     return userOut

   def showResult(self, pvlist):
      self.lock.acquire()
      if (pvlist):
         frest = open(self.fpath, "w")
         for h in self.data.keys():
            for port in self.data[h].keys():
               for cid in self.data[h][port].keys():
                  if (cid == 'user' or cid == 'hostname' or (not self.data[h][port][cid]['sid'])):
                     continue
                  if (self.data[h][port][cid]['pv'] in pvlist):
                     dUser = {} 
                     dUser['val'] = self.tsKeyToTimestamp(self.data[h][port][cid]['val'])
                     dUser['write'] = self.tsKeyToTimestamp(self.data[h][port][cid]['write'])
                     dUser['pv'] = self.data[h][port][cid]['pv']
                     dUser['dstHost'] = f'{self.data[h][port][cid]["dstHost"]}:{self.data[h][port][cid]["dstPort"]}'
                     frest.write(f'******* host: {h}  port: {port} *********** \n')
                     strJson = json.dumps(dUser, indent=4, ensure_ascii=False, default=serialize_sets)
                     frest.write(strJson)
                     print(f'\n******* host: {h}  port: {port} ***********')
                     print(strJson)
         frest.close()
      else:
         #strJson = json.dump(self.data, f, indent=4, ensure_ascii=False, default=serialize_sets)
         strJson = json.dumps(self.data, indent=4, ensure_ascii=False, default=serialize_sets)
         print(f'******* All Data stored ********** ')
         print(strJson)
      self.lock.release()

   def __repr__(self):
      json_str = json.dumps(copy.deepcopy(self.data), indent=4, ensure_ascii=False, default=serialize_sets) 
      return json_str



def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj

