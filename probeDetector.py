from scapy.all import *
from optparse import *
from scapy.utils import PcapReader


probeReqs = {}

def sniffProbe (data):
    if data.haslayer(Dot11ProbeReq):
        netName = data.getlayer(Dot11ProbeReq).info.decode('utf-8')
        source_address =  data.addr2
        if netName != '' and  source_address not in probeReqs:
            probeReqs[source_address] = []
        if netName != '' and netName not in probeReqs[source_address]:    
            probeReqs[source_address].append(netName)


if __name__ == "__main__":
    
    usage = '%prog -w <interface> '
    parser = OptionParser(usage,version='%grop 1.0 beta' )
    parser.add_option('-w','--wireless_interface',action='store',type='string',dest='interface',help='Enter your  wireless interface')
    parser.add_option('-o','--outFile',action = 'store', type ='string' , dest='OutFile',default='None',help = 'the filename you want to  save')
    parser.add_option('-i','--inputFile',action = 'store', type = 'string' , dest='InFile',default='None', help = 'the filename you want to analysis ')
    (options,args) = parser.parse_args()
    
    
    if not options.interface and (options.InFile == 'None') :
        parser.print_help()
        exit()
    else:
        if options.InFile != 'None':
            pak = rdpcap(options.InFile)
            for data in pak:
                sniffProbe(data)
            for key in probeReqs:    
                print('[+]Client MAC>>' + key)
                print('[-]the client connected WLAN before:')
                for value in probeReqs[key]:
                    print('\t[×]' + value)
        else:    
            try:
                sniff(iface=options.interface, prn=sniffProbe)
            #本地文件分析
            except OSError:
                print('[Error]: Network is down, check your wireless interface!')
                exit()
            
