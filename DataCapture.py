from dataclasses import dataclass, field
from typing import List 
from multiprocessing import Queue, Process, cpu_count
import re, datetime, sys, os, time, glob
sys.path.append(f'{os.getcwd()}/pyshark.git/src')
import pyshark 

class DataCapture(Process):

   def __init__(self, lhost : List, lhexcl : List, bpfilter : str, mainQ : Queue, interface=None, fpath=None):
      Process.__init__(self)
      self.param               = {'-X': f'lua_script:{os.getcwd()}/tshark-plugin/ca.lua'}
      self.bpfilter     : str  = bpfilter
      self.interface    : str  = interface
      self.mainQ        : Queue = mainQ
      self.lhost        : List = lhost
      self.lhexcl       : List = lhexcl # List host to exclude capturing package. 
      self.fpath        = fpath
      
   def run(self):
      if (self.fpath):
         self.readFile()
      elif(self.interface):
         self.liveCapture()
      else:
         print('The PyShark process needs a path file definition or an ethernet card interface')

   #################################
   def readFile(self):
      try:
         if os.path.isfile(self.fpath):
            self.__readFile__(self.fpath, self.mainQ)
         elif os.path.isdir(self.fpath):
            self.processFiles()        
         else:
            print('Bad Option, the path provided is not a directory or file')
      except Exception as e:
         print(e)
         print("TODO. tshark had an error or a file was removed")
       
   #################################
   # parameters:
   #    q : This is a multiprocessing.queue which is shared
   #        with the ProcessPackage. 
   #  path: This is path file which will be read. 
   #################################
   def __readFile__(self, path, q):  
      try:
         cap = pyshark.FileCapture(path, custom_parameters=self.param)
         for p in cap:
            q.put(p)
      except Exception as e:
         print(e)
         print("TODO. tshark had an error or a file was removed")

   #################################
   def getInfoFiles(self, fpath, filesD):
      fpath = fpath if fpath.endswith('/') else fpath + '/'
      # There is a problem with the nfs performance which
      # can be that a file has not been updated in one second.
      lfilter = filter(os.path.isfile, glob.glob(fpath + '*'))
      lfiles = sorted(lfilter, key=os.path.getmtime)
      updated = False
      nFilesReady = 0
      for fname in lfiles:
         ifile = os.stat(fname) 
         ifileS = filesD.get(fname)
         if ifileS:
             if (ifileS['st_size'] != 0 and ifile.st_size == ifileS['st_size']):
                filesD[fname]['updated'] = False
                nFilesReady += 1
                continue
         updated = True
         filesD[fname] = {'st_size' : ifile.st_size, 'updated' : True}
      return updated, lfiles, nFilesReady

   def waitForAllProc(self, dMultproc):
      try:
        # The first proccess is introducing the packages
        # in the main queue which is reading the consumer
        #if not dMultproc['lProc'][0].is_alive():
        #    return 0
        dMultproc['lProc'][0].join(60) # No more 60 seconds
        qSize1 = dMultproc['qList'][0].qsize()
        nProc = len(dMultproc['lProc'])
        sizeCurrentQ = 0
        for i in range(1, nProc):
           #print(f'iteration {i} ')
           #dMultproc['lProc'][i].join(20) # No more 20 seconds
           n = 0
           try:
             q =  dMultproc['qList'][i]
             q0 = dMultproc['qList'][0]
             while (True):
                p = q.get(timeout=1)
                q0.put(p)
                n=n+1
           except Exception as e:
                print(e)
                print(f'Q({i}): {n} pkgs transfered.\nQ(0).Init:{qSize1} pkgs - Current: {dMultproc["qList"][0].qsize()} pkgs')
           n = 0
        return 1
      except Exception as e:
        print(f'Error in waitForAllProc, Exception {e} ')
        return 0


   #################################

   def processFiles(self):
      t1 = time.time()
      filesD = {}
      numProc = cpu_count() 
      maxQueues = max(1, numProc - 2) # Two process are using for the consumer and the main process
      dMultproc = {'qList' : [], 'lProc' : [], 'lPath' : []}
      dMultproc['qList'].append(self.mainQ)
      dMultproc['lProc'].append(None)
      for i in range (1,maxQueues):
          dMultproc['qList'].append(Queue())
          dMultproc['lProc'].append(None)

      while (True):
         updated, lfiles, nFilesReady = self.getInfoFiles(self.fpath, filesD)
         # I have taken the condtion nFilesReady < numProc because
         # there is delay in the nfs files updating which makes that 
         # the getInfoFiles creates the files are not being updated. 
         # We can not remove the last file because could be used by
         # tshark in the other machine and if you remove it the tshark
         # will crash. 
         if (not filesD or nFilesReady <= maxQueues):
             time.sleep(1)
             continue
         nIter = nFilesReady
         if (nIter > maxQueues):
            nIter = maxQueues
         for i in range(nIter):
            dMultproc['lProc'][i] = Process(target=self.__readFile__, args=(lfiles[i], dMultproc['qList'][i]))
            dMultproc['lProc'][i].start()

         self.waitForAllProc(dMultproc)
         for i in range(nIter):
             try:
                os.remove(lfiles[i])
             except Exception as e2:
                 print("Error removing the file")
                 print(e2)
             filesD.pop(lfiles[i])     

         t2 = time.time()
         print(f'-Time spent analysing the previous {nIter} files was {t2 - t1} secs')
         t1 = t2
         
   #################################
   def newPackage(self, p):
      self.mainQ.put(p)
   #################################
   def liveCapture(self):
      bpf_filterOpt=''
      if (self.lhost):
         for i in range(0,len(self.lhost)):
            bpf_filterOpt+='host ' + self.lhost[i] 
            if (i < len(self.lhost)-1):
                 bpf_filterOpt+=' or '

      if (self.lhexcl):
         if (self.lhost):
            bpf_filterOpt+=' and ( '
         for i in range(0,len(self.lhexcl)):
            bpf_filterOpt+='not host ' + self.lhexcl[i]
            if (i < len(self.lhexcl)-1):
               bpf_filterOpt+=' or '
         bpf_filterOpt+=')'

      print(f'Capture filter is {bpf_filterOpt}')
      print(f'bpfilter: {self.bpfilter}')
      self.param['-f'] = self.bpfilter if self.bpfilter else bpf_filterOpt
      print(self.param)
      cap = pyshark.LiveCapture(interface=self.interface, custom_parameters=self.param)
      cap.set_debug()
      cap.apply_on_packets(self.newPackage)

