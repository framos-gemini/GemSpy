import multiprocessing
import threading
import click
import re
import time, sys
import json
import jsonpickle
from json import JSONEncoder
from Deploy import Deploy

@click.group(chain=True)
@click.option('--debug/--no-debug', default=False)
@click.option('--pvfilter', default=None, help='List of pvNames separated by semicolon which you want to spy. This will discard all the remain pv names arrived.')
@click.option('--bpfilter', default=None, help='Berkeley Packet Filter BPF. This option allow to user to specified the custom capture filter following under BPF syntax. This option is not compatible with --lhost and --lhexcl')
@click.option('--lhost', default=None, help='List of IP ADDRESS of the hosts you want to spy on.The specified host can be a source or a destination host. This parameter is taken into account in packet capture. The host specified can be source or destinity. This parameter is taken in account on package capture')
@click.option('--lhexcl', default=None, help='List of IP ADDRESS of the hosts that you want to exclude of the gathering information. The host specified can be source or destinity. This parameter is taken in account on package capture')
@click.option('--live', default=None, help='This option requires the name of the interface which will be used to capture packets from the network. For example --live eno2. One of the --live or capfile options should be provided')
@click.option('--capfile', default=None, help='This option requires the path of the cap file to analyse. For example --capfile /tmp/filename.cap. One of the --live or capfile options should be provided')
@click.option('--jsonoutput', nargs=2, default=(None,0), type=click.Tuple([str,int]), help='This parameter is a a Tuple. The first parameter  indicates the json path file where you want to store the data. The second parameter indicates the time that you want to store this information to the file')
@click.pass_context
#def cli(ctx, debug, pvfilter, bpfilter, pvlist, lhost, lhexcl, live, capfile, printdata, jsonoutput):
def cli(ctx, debug, pvfilter, bpfilter, lhost, lhexcl, live, capfile, jsonoutput):
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    ctx.obj['lpvnames'] = re.split(';', pvfilter) if pvfilter is not None else []
    ctx.obj['lhost'] = re.split(';', lhost) if lhost is not None else []
    ctx.obj['lhexcl'] = re.split(';', lhexcl) if lhexcl is not None else []
    ctx.obj['live'] = live
    ctx.obj['capfile'] = capfile
    ctx.obj['jsonoutput'] = jsonoutput[0]
    ctx.obj['storedata']  =  jsonoutput[1]
    ctx.obj['bpfilter'] = bpfilter
    if ((not ctx.obj['live'] and not ctx.obj['capfile']) or \
        (ctx.obj['bpfilter'] and ( ctx.obj['lhexcl'] or ctx.obj['lhost'] ))): 
       print(f'Error detected. Possible errors ')
       print(f'You should provide atleast --live or --capfile option. ')
       print(f'If you provide bpfilter, you have to provide  --lhexcl or --lhexcl option too.')
       click.echo(ctx.get_help())
       return 0
   


@cli.command('runNoGui')
@click.option('--pvlist', default=None, help='List of pvNames separated by semicolon which you want to show each time specified in the printdata')
@click.option('--printdata', default=0, help='This parameter indicates that the information is going to be show each seconds.')
@click.pass_context
def runNoGui(ctx, pvlist, printdata):
    ctx.obj['printdata'] = printdata
    ctx.obj['pvlist'] = re.split(';', pvlist) if pvlist is not None else []

    if ((not ctx.obj['live'] and not ctx.obj['capfile']) or \
        (ctx.obj['bpfilter'] and ( ctx.obj['lhexcl'] or ctx.obj['lhost'] ))): 
       return 0

    print(f'##### pvfilter: {ctx.obj["lpvnames"]} ')
    print(f'##### storedata: {ctx.obj["storedata"]} ')
    deploy = Deploy()
    dataClient = deploy.startApp(ctx.obj['capfile'], ctx.obj['lpvnames'], ctx.obj['bpfilter'], ctx.obj['pvlist'],  ctx.obj['lhost'], ctx.obj['lhexcl'], ctx.obj['live'], ctx.obj['printdata'],ctx.obj['jsonoutput'], ctx.obj['storedata'])
    print(" ************* GEMSPY OUTPUT ************************")
    print(dataClient)
    print("finished successfully, this is the output. If there is a lot of information output use the --pvlist option to reduce it.")
    


@cli.command('runGui')
@click.pass_context
def runGui(ctx):
    click.echo('The desktop interface has not been implemented yet')

if __name__ == '__main__':
   commands = (
        'runNoGui --help',
        'runNoGui',
        '--help',
   )

   #   cli(cmd.split(), obj={})
   cli(obj={})
