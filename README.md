# GemSpy
GemSpy is a tool capable of analyzing the network traffic, allowing to know which commands have been sent by clients to IOCs.

It can also be used to investigate a specific problem occurring in production. For example, we can deploy the tool to get all the messages sent by one or more clients to the IOC that cause an anomalous situation. The tool is able to persist these messages in the order in which they were sent.

**Python Version**
The first GemSpy version has been developed for python version higher than 3.7.3

## Instalation
git clone git@github.com:framos-gemini/GemSpy.git

## Run
### General Options
```
Usage: spy.py [OPTIONS] COMMAND1 [ARGS]... [COMMAND2 [ARGS]...]...

Options:
  --debug / --no-debug
  --pvfilter TEXT                 List of pvNames separated by semicolon which
                                  you want to spy. This will discard all the
                                  remain pv names arrived.
  --bpfilter TEXT                 Berkeley Packet Filter BPF. This option
                                  allow to user to specified the custom
                                  capture filter following under BPF syntax.
                                  This option is not compatible with --lhost
                                  and --lhexcl
  --lhost TEXT                    List of IP ADDRESS of the hosts you want to
                                  spy on.The specified host can be a source or
                                  a destination host. This parameter is taken
                                  into account in packet capture. The host
                                  specified can be source or destinity. This
                                  parameter is taken in account on package
                                  capture
  --lhexcl TEXT                   List of IP ADDRESS of the hosts that you
                                  want to exclude of the gathering
                                  information. The host specified can be
                                  source or destinity. This parameter is taken
                                  in account on package capture
  --live TEXT                     This option requires the name of the
                                  interface which will be used to capture
                                  packets from the network. For example --live
                                  eno2. One of the --live or capfile options
                                  should be provided
  --capfile TEXT                  This option requires the path of the cap
                                  file to analyse. For example --capfile
                                  /tmp/filename.cap. One of the --live or
                                  capfile options should be provided
  --jsonoutput <TEXT INTEGER>...  This parameter is a a Tuple. The first
                                  parameter  indicates the json path file
                                  where you want to store the data. The second
                                  parameter indicates the time that you want
                                  to store this information to the file
  --help                          Show this message and exit.

Commands:
  runGui
  runNoGui
```
### Run with runNoGui command
```
Usage: spy.py runNoGui [OPTIONS]

Options:
  --pvlist TEXT        List of pvNames separated by semicolon which you want
                       to show each time specified in the printdata
  --printdata INTEGER  This parameter indicates that the information is going
                       to be show each seconds.
  --help               Show this message and exit.
 ``` 
 ### Run with runGui command 
 This opiton has not been implemented yet. 
 
 ### Example Live Mode. 
 ```
 python spy.py --live='eno2' --bpfilter="not (tcp port 56118 and ip host 139.229.35.40 and tcp port 22 and ip host 172.17.50.30) and host 172.17.65.100 and (host 172.16.44.50)" --jsonoutput /tmp/sample.json 120  runNoGui --printdata=60  --pvlist="aom:inShCtrl.A;aom:apply.DIR"
 ```
 ### Example Read File Mode
 ```
 python spy.py --capfile ./cap-file-documentation/aom_00001_20220608100121.cap runNoGui
 ```
 ### Example of deployment used in GEMS
 #### Run Tshark on cponetl-lp1
 ```
 nohup /usr/sbin/tshark -f "not (tcp port 56118 and ip host 139.229.35.40 and tcp port 22 and ip host 172.17.50.30) and host 172.17.65.100 and (host 172.16.44.50 or host 172.16.44.51 or host 172.16.44.52 or host 172.16.44.53 or host 172.17.44.50 or host 172.17.44.51 or host 172.17.44.52 or host 172.17.44.53 or host 172.17.65.10 or 172.17.44.64 or 172.17.65.21 or 172.17.65.22 or 172.17.104.21 or 172.17.44.63) and greater 68 " -b filesize:500 -b files:5000 -w /data/sto/tshark-rawdata4/aom-inShutter > ./tshark-log.txt 2>&1 &
 ```
 #### Run GemSpy on cponetl-lp1
```
nohup python spy.py --capfile=/data/sto/tshark-rawdata4/ --jsonoutput /home/framos/gemspy-aom-10162022.txt 120 --pvlist="aom:inShCtrl.A;aom:apply.DIR;aom:TEMxCondScheme" --pvfilter="aom:inShCtrl.A;aom:apply.DIR;aom:TEMxCondScheme" runNoGui > /tmp/spy.run.txt 2>&1 &
```

 
