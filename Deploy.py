import multiprocessing
import threading
from DataCapture import DataCapture
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
       q = multiprocessing.Queue()
       l = threading.Lock()
       dataClient = DataClients(lock=l, fpath='./spy-result.txt', lpvFilter=lpvfilter)
       procPck = ProcessPackage(q, dataClient, lock=l)  
       pys = DataCapture(lhostP, lhexcl, bpfilter, q, interface, pathFile )
       #pth1 = threading.Thread(target=procPck.readPackgCon)
       pys.start()
       procPck.start()
       t1 = int(time.time())
       t0 = t1
       twriteL = t1
       while (pys.is_alive()):
          pys.join(5)
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
       
       #procPck.terminate()
       procPck.setBreakLoop(True)
       return dataClient
