from scapy.all import *
from optparse import *
from scapy.utils import PcapReader
import os
import sys
import time
import threading

threads = []

class myThread(threading.Thread):
    
    def __init__(self,threadID,name):
        threading.Thread.__init__(self)
        self.threadID =  threadID
        self.name = name
    def run_cap(self):
        try:
            data = sniff(count=10000000,prn = lambda x :x.summary(),iface=options.interface)
        except:
            pass
    def run_cout(self):
        time.sleep(7)
        print_result()
    def run_sniff(self):
        print('starting analysis...')
        sniff(iface=options.interface, prn=sniffProbe)




probeReqs = {}

def sniffProbe (data):
    if data.haslayer(Dot11ProbeReq):
        netName = data.getlayer(Dot11ProbeReq).info.decode('utf-8')
        source_address =  data.addr2
        if netName != '' and  source_address not in probeReqs:
            probeReqs[source_address] = []
        if netName != '' and netName not in probeReqs[source_address]:    
            probeReqs[source_address].append(netName)

def output(file):#分析进程结束后输出
    if file == 'None':
        for key in probeReqs:    
            print('[+]Client MAC>>' + key)
            print('[-]the client connected WLAN before:')
            for value in probeReqs[key]:
                print('\t[×]' + value)
    if file !='None':
        name = file + '.txt'
        f = open(name,'w')
        for key in probeReqs:
            f.write('[+]Client MAC>>' + key)
            f.write('[-]the client connected WLAN before:')
            for value in probeReqs[key]:
                f.write('\t[×]' + value)
        f.close()

def save_pacp(save_opt, data):
    
    if save_opt:    
        TL = True
        if os.path.exists('./cap'):
            pass
        else:    
            os.mkdir('./cap')
            if TL:
                pktdump = PcapWriter('./cap/packets.pcap',append=True, sync= True)
                TL = False
            pktdump.write(data)
    else:
        return

def print_result():#动态打印结果
    os.system('clear')
    for key in probeReqs:    
        print('[+]Client MAC>>' + key)
        print('[-]the client connected WLAN before:')
        for value in probeReqs[key]:
            print('\t[×]' + value)

if __name__ == "__main__":
    
    if os.getuid() != 0:
        print('Please run this script as root')
        sys.exit(1)

    usage = '%prog -w <wireless_interface> '
    parser = OptionParser(usage,version='%grop 1.0 beta' )
    parser.add_option('-w','--wireless_interface',action='store',type='string',dest='interface',help='Enter your  wireless interface')
    parser.add_option('-o','--outFile',action = 'store', type ='string' , dest='OutFile',default='None',help = 'the filename you want to  save')
    parser.add_option('-i','--inputFile',action = 'store', type = 'string' , dest='InFile',default='None', help = 'the filename you want to analysis ')
    parser.add_option('-s','--save',action = 'store_true', dest = 'save', default=False, help = 'save the pcap packet [default]:false')
    (options,args) = parser.parse_args()
    
    
    if not options.interface and (options.InFile == 'None') :
        parser.print_help()
        exit()
    else:
        if options.InFile != 'None':
            pak = rdpcap(options.InFile)
            for data in pak:
                sniffProbe(data)
            output(options.OutFile)
        else:    
            try:
                pass#实时抓取分析
            except OSError:
                print('[Error]: Network is down, check your wireless interface!')
                sys.exit(1)

