import multiprocessing
import threading
from PyShark import PyShark
from HashClient import HashClient
from ProcessPackage import ProcessPackage
import click
import re
import time, sys
import json
import jsonpickle
from json import JSONEncoder
import time


@click.group(chain=True)
@click.option('--debug/--no-debug', default=False)
@click.option('--pvfilter', default=None, help='List of pvNames separated by semicolon which you want to spy. This will discard all the remain pv names arrived. This option is useful in order not to crash the system')
@click.option('--bpfilter', default=None, help='Berkeley Packet Filter BPF. This option allow to user to specified the custom capture filter following under BPF syntax. This option is not compatible with --lhost and --lhexcl')
#@click.option('--pvfilter', default=None, nargs=2, type=click.Tuple([str,int]) help='This parameter is a tuple, where the first parameter is a list of pvNames separated by semicolon which you want to spy. Meanwhile the second parameter is number of seconds to show the i. This will discard all the remain pv names arrived. This option is useful in order not to crash the system. Example of use: --pvfilter "pvname1;pvname2" 5 ')
@click.option('--pvlist', default=None, help='List of pvNames separated by semicolon which you want to show each time specified in the printdata')
@click.option('--lhost', default=None, help='List of host ip address that you want to gather information. The host specified can be source or destinity. This parameter is taken in account on package capture')
@click.option('--lhexcl', default=None, help='List of host ip address that you want to exclude of the gathering information. The host specified can be source or destinity. This parameter is taken in account on package capture')
@click.option('--live', default=None, help='This option requires the name of the interface which will be used to capture packets from the network. For example --live eno2. One of the --live or capfile options should be provided')
@click.option('--capfile', default=None, help='This option requires the path of the cap file to analyse. For example --capfile /tmp/filename.cap. One of the --live or capfile options should be provided')
@click.option('--printdata', default=0, help='This parameter indicates that the information is going to be show each seconds.')
@click.option('--jsonoutput', nargs=2, default=(None,None), type=click.Tuple([str,int]), help='This parameter is a a Tuple. The first parameter  indicates the json path file where you want to store the data. The second parameter indicates the time that you want to store this information to the file')
@click.pass_context
def cli(ctx, debug, pvfilter, bpfilter, pvlist, lhost, lhexcl, live, capfile, printdata, jsonoutput):
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    ctx.obj['lpvnames'] = re.split(';', pvfilter) if pvfilter is not None else []
    ctx.obj['pvlist'] = re.split(';', pvlist) if pvlist is not None else []
    ctx.obj['lhost'] = re.split(';', lhost) if lhost is not None else []
    ctx.obj['lhexcl'] = re.split(';', lhexcl) if lhexcl is not None else []
    ctx.obj['live'] = live
    ctx.obj['capfile'] = capfile
    ctx.obj['printdata'] = printdata
    lpath, nSecs = jsonoutput if jsonoutput else (None, None)
    ctx.obj['jsonoutput'] = lpath
    ctx.obj['storedata'] = nSecs
    ctx.obj['bpfilter'] = bpfilter
    
    #if (live is None and capfile is None):
    if ((not live  and not capfile) or (bpfilter and ( lhexcl or lhost ))): 
       print(f'Error detected, you should provide --live or --capfile option')
       click.echo(ctx.get_help())

    if (pvfilter and pvlist):
       ctx.obj['pvlist'] = ctx.obj['lpvnames']
       


@cli.command('runNoGui')
@click.pass_context
def runNoGui(ctx):
    print(f'##### pvfilter: {ctx.obj["lpvnames"]} ')
    
    myHash = startApp(ctx.obj['capfile'], ctx.obj['lpvnames'], ctx.obj['bpfilter'], ctx.obj['pvlist'],  ctx.obj['lhost'], ctx.obj['lhexcl'], ctx.obj['live'], ctx.obj['printdata'],ctx.obj['jsonoutput'], ctx.obj['storedata'])
    print(" ************* GEMSPY OUTPUT ************************")
    print(myHash)
    print("finished successfully, this is the output. If there is a lot of information output use the --pvlist option to reduce it.")
    


@cli.command('runGui')
@click.pass_context
def runGui(ctx):
    click.echo('The desktop interface has not been implemented yet')

def startApp(pathFile, lpvfilter, bpfilter, pvlist, lhostP, lhexcl,interface, printdata, pJsonfile, nSecStore):
    numProc = multiprocessing.cpu_count() - 2
    # the queue[0] is the main which will be shared with 
    # the thread consumer
    qList = []
    for i in range (numProc):
        qList.append(multiprocessing.Queue())
    l = threading.Lock()
    myHash = HashClient(lock=l, fpath='/tmp/spy-result.txt', lpvFilter=lpvfilter)
    procPck = ProcessPackage(qList[0], myHash, lock=l)  
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
          myHash.showResult(pvlist)
          procPck.printQueueSize()
          t1 = t2

       if (nSecStore > 0 and (t2 - twriteL) > nSecStore):
          myHash.writeLog(pJsonfile)
          twriteL = t2
          sys.stdout.flush()
    
    p1.terminate()
    procPck.setBreakLoop(True)
    return myHash

if __name__ == '__main__':
   cli(obj={})
      
