import re
from dataclasses import dataclass, field
import datetime
import sys
import multiprocessing
import copy
from typing import List 
import sys, os
#sys.path.append('/home/software/fr/gemspy/pyshark.git/src')
sys.path.append('/home/framos/fr/gemspy/pyshark.git/src')
import pyshark 
import time, glob


@dataclass
class PyShark:
   #param = {'-X': 'lua_script:/home/software/ca2.lua', '-f': '"host 172.16.44.50 or host 172.17.65.100 and (not host 172.17.5.96 or not host 172.17.5.95)"'}
   #param = {'-X': 'lua_script:/home/framos/fr/gemspy/ca2.lua'}
   param              = {'-X': 'lua_script:/home/framos/fr/gemspy/ca.lua'}
   bpfilter     : str = '' 
   cap                = None
   interface    : str = 'eno1'
   dMultproc          = {'qList' : None, 'lProc' : [], 'lPath' : []}
   #qList        : multiprocessing.Queue = None
   lhost : List = field(default_factory=list) 
   lhexcl : List = field(default_factory=list) 
   isProcessing : bool =  False

   #################################
   def readFile(self, qList, file_path):
      try:
         self.dMultproc['qList'] = qList
         if os.path.isfile(file_path):
            self.__readFile__(file_path, self.dMultproc['qList'])
         elif os.path.isdir(file_path):
            self.processFiles(file_path)        
         else:
            print('Bad Option, the path provided is not a directory or file')
      except Exception as e:
         print(e)
         print("TODO. tshark had an error or a file was removed")
       
   #################################
   def __readFile__(self, path, q):
      try:
         self.cap = pyshark.FileCapture(path, custom_parameters=self.param)
         for p in self.cap:
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

   def waitForAllProc(self, nProc):
      try:
        # The first proccess is introducing the packages
        # in the main queue which is reading the consumer
        if not self.dMultproc['lProc'][0].is_alive():
            return 0
        self.dMultproc['lProc'][0].join(60) # No more 60 seconds
        qSize1 = self.dMultproc['qList'][0].qsize()
        for i in range(1, nProc):
           #print(f'iteration {i} ')
           n = 0
           try:
             q =  self.dMultproc['qList'][i]
             q0 = self.dMultproc['qList'][0]
             while (True):
                p = q.get(timeout=1)
                q0.put(p)
                n=n+1
           except Exception as e:
                print(e)
                qSize1 = self.dMultproc['qList'][0].qsize()
                print(f'Q({i}): {n} pkgs transfered.\nQ(0).Init:{qSize1} pkgs - Current: {self.dMultproc["qList"][0].qsize()} pkgs')
           n = 0
        return 1
      except Exception as e:
        print(f'Error in waitForAllProc, Exception {e} ')
        return 0


   #################################

   def processFiles(self, file_path):
      t1 = time.time()
      filesD = {}

      numProc = len(self.dMultproc['qList'])
      self.dMultproc['lProc'] = [None] * len(self.dMultproc['qList'])
      while (True):
         updated, lfiles, nFilesReady = self.getInfoFiles(file_path, filesD)
         # I have taken the condtion nFilesReady < numProc because
         # there is delay in the nfs files updating which makes that 
         # the getInfoFiles creates the files are not being updated. 
         # We can not remove the last file because could be used by
         # tshark in the other machine and if you remove it the tshark
         # will crash. 
         if (not filesD or nFilesReady <= numProc):
             time.sleep(1)
             continue
         nIter = nFilesReady
         if (nIter > numProc):
            nIter = numProc
         for i in range(nIter):
            self.dMultproc['lProc'][i] = multiprocessing.Process(target=self.__readFile__, args=(lfiles[i], self.dMultproc['qList'][i]))
            self.dMultproc['lProc'][i].start()

         self.waitForAllProc(nIter)
         for i in range(nIter):
             try:
                os.remove(lfiles[i])
             except Exception as e2:
                 print("Error removing the file")
                 print(e2)
             filesD.pop(lfiles[i])     
             self.isProcessing = True

         t2 = time.time()
         print(f'-Time spent analysing the previous {nIter} files was {t2 - t1} secs')
         t1 = t2
         
   #################################
   def newPackage(self, p):
      self.q.put(p)
   #################################
   def liveCapture(self, q):
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
      self.cap = pyshark.LiveCapture(interface=self.interface, custom_parameters=self.param)
      self.cap.set_debug()
      self.q = q
      self.cap.apply_on_packets(self.newPackage)
      return self.cap

