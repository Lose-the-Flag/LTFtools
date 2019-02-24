from optparse import *
from scapy.all import *
from scapy.utils import PcapReader
import os
import sys
import time
from threading import *

pkt_counter = 0
threads = []#线程数组
pkts =[] #用于保存实时抓取流量的所有流量


def cap():#可以更改加入参数来确定每抓多少个包保存一次
    global pkts
    #global pkt_counter
    x = []
    while True:
        x = sniff(iface=options.interface,count=100)
        #pkt_counter = pkt_counter + 100
        try:
            pkts.append(x)
            save_pacp(options.save,pkts)
        except:
            pass
def run_cout():#可以加入一个刷新频率的参数
    while True:    
        print_result()
        time.sleep(2)
def run_sniff():#可以设置一个默认抓包个数的参数
    print('starting analysis...')
    while True:
        sniff(iface=options.interface, prn=sniffProbe)

#线程
cap_thread = threading.Thread(target=cap,name="cap_thread")
sniff_thread = threading.Thread(target=run_sniff,name="sniff_thread")
threads.append(sniff_thread)
cout_thread = threading.Thread(target=run_cout,name="sniff_thread")
threads.append(cout_thread)



probeReqs = {}#用于保存捕捉到的

def sniffProbe (data):
    if data.haslayer(Dot11ProbeReq):
        try:
            netName = data.getlayer(Dot11ProbeReq).info.decode('utf-8')#编码方式可能有问题
        except:
            netName = data.getlayer(Dot11ProbeReq).info.decode('GBK')#编码方式可能有问题
        
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
    print("--------------------RESULT--------------------")
    for key in probeReqs:    
        print('[+]Client MAC>>' + key)
        print('[-]the client connected WLAN before:')
        for value in probeReqs[key]:
            print('\t[×]' + value)

def save_result():#保存输出结果
    pass

if __name__ == "__main__":
    
    if os.getuid() != 0:
        print('Please run this script as root')
        sys.exit(1)

    usage = '%prog -w <wireless_interface> '
    parser = OptionParser(usage,version='%grop 1.0 beta' )
    parser.add_option('-w','--wireless_interface',action='store',type='string',dest='interface',help='Enter your  wireless interface')
    parser.add_option('-o','--outFile',action = 'store', type ='string' , dest='OutFile',default='None',help = 'the filename you want to  save')
    parser.add_option('-i','--inputFile',action = 'store', type = 'string' , dest='InFile',default='None', help = 'the filename you want to analysis ')
    parser.add_option('-s','--save',action = 'store_true', dest = 'save', default=False, help = 'save the pcap packet or not [default]:not')
    (options,args) = parser.parse_args()
    
    
    if not options.interface and (options.InFile == 'None') :
        parser.print_help()
        exit()
    else:#分析已存在流量包
        if options.InFile != 'None':
            pak = rdpcap(options.InFile)
            for data in pak:
                sniffProbe(data)
            print_result()
            if options.OutFile != 'None':
                pass
        else:    #一边实时分析一边保存抓包结果(加-s参数)
            if options.save == True:
                try:
                    for t in threads:
                        t.setDaemon(True)
                        t.start()
                        print("线程"+t.getName()+"启动")
                    cap_thread.setDaemon(True)
                    cap_thread.start()
                    sniff_thread.join(300)#阻塞主进程
                    print("--------------默认开启五分钟结束--------------")
                    if options.OutFile != 'None':
                        pass
                except OSError:
                    print('[Error]: Network is down, check your wireless interface!')
                    sys.exit(1)
            else:#多线程实时抓取分析(不加参数)
                try:
                    for t in threads:
                        t.setDaemon(True)
                        t.start()
                        print("线程"+t.getName()+"启动")
                    sniff_thread.join()#阻塞主进程
                    print("--------------默认开启五分钟结束--------------")
                    if options.OutFile != 'None':
                        pass
                except OSError:
                    print('[Error]: Network is down, check your wireless interface!')
                    sys.exit(1)
