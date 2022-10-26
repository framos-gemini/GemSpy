import multiprocessing
import threading
from PyShark import PyShark
from DataClients import DataClients
from ProcessPackage import ProcessPackage
import time, sys
from dataclasses import dataclass, field

@dataclass
class Deploy:
   def startApp(self, pathFile, lpvfilter, bpfilter, pvlist, lhostP, lhexcl,interface, printdata, pJsonfile, nSecStore):
       numProc = max(1,multiprocessing.cpu_count() - 2)
       print (f'numProc: {numProc}')
       # the queue[0] is the main which will be shared with 
       # the thread consumer
       qList = []
       for i in range (numProc):
           qList.append(multiprocessing.Queue())
       l = threading.Lock()
       dataClient = DataClients(lock=l, fpath='./spy-result.txt', lpvFilter=lpvfilter)
       procPck = ProcessPackage(qList[0], dataClient, lock=l)  
       pys = PyShark(interface=interface, lhost=lhostP, lhexcl=lhexcl, bpfilter=bpfilter)
       p1 = None
       if (pathFile):
          p1 = multiprocessing.Process(target=pys.readFile, args=(qList,pathFile))         
       else:
          # TODO, it is not updated with the last change, i.e. not supported the qList
          p1 = multiprocessing.Process(target=pys.liveCapture, args=(qList[0],))
       pth1 = threading.Thread(target=procPck.readPackgCon)
       p1.start()
       pth1.start()
       t1 = int(time.time())
       t0 = t1
       twriteL = t1
       while (p1.is_alive()):
          p1.join(5)
          if (printdata == 0 and nSecStore == 0):
             print('.', end=" ")
          t2 = int(time.time())
          if (printdata > 0 and (  (t2 - t1) > printdata  )):
             dataClient.showResult(pvlist)
             procPck.printQueueSize()
             t1 = t2

          if (nSecStore > 0 and (t2 - twriteL) > nSecStore):
             dataClient.writeLog(pJsonfile)
             twriteL = t2
             sys.stdout.flush()
       
       p1.terminate()
       procPck.setBreakLoop(True)
       return dataClient
