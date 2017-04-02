from struct import *
from impacket import ImpactDecoder, ImpactPacket
import socket
import Pmw
import pcapy
import thread
import sys
import tkMessageBox

interface=''
detail=''
protocols={6:"TCP", 1: "ICMP", 17: "UDP"}

def sniffme():
	global interface
	cap = pcapy.open_live(interface , 65536 , 1 , 0)
	#start sniffing packets
	while(1):
		(header, packet) = cap.next()
		#print ('captured %d bytes, truncated to %d bytes' %(header.getlen(), header.getcaplen()))
		parse_packet(packet)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
 
#function to parse a packet
def parse_packet(packet) :
    global protocols
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    values=[]
    nrow=[]
    values.append(eth_addr(packet[0:6]))
    values.append(eth_addr(packet[6:12]))
    values.append(str(eth_protocol))
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]
        
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        values.append(str(version))
        values.append(str(ihl))
        values.append(str(ttl))
        if protocol in protocols:
            values.append(protocols[protocol])
        else:
            values.append("Other")
        values.append(str(s_addr))
        values.append(str(d_addr))
        nrow.append(values)
        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
 
            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)
             
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
             
            det = 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
            
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            fmt='!'
            for i in range(len(data)):
                fmt = fmt + 'c'
            nrow.append(det) 
            nrow.append(''.join(unpack(fmt, data)))
             
        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]
 
            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            det = 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            fmt='!'
            for i in range(len(data)):
                fmt = fmt + 'c'
            nrow.append(det) 
            nrow.append(''.join(unpack(fmt, data)))
            
        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            det = 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
            data = packet[h_size:]
            fmt='!'
            for i in range(len(data)):
                fmt = fmt + 'c'
            nrow.append(det) 
            nrow.append(''.join(unpack(fmt, data)))
            
 
        #some other IP packet like IGMP
        else :
            det = 'Protocol other than TCP/UDP/ICMP'
            nrow.append(det)
            nrow.append('')
        print 'Destination MAC: ' + str(nrow[0][0]) + ' Source MAC: ' + str(nrow[0][1]) + '\nProtocol: ' + str(nrow[0][2]) + ' Version: ' + str(nrow[0][3]) + ' IP HLen: ' + str(nrow[0][4]) + ' TTL: ' + str(nrow[0][5]) + ' IP Protocol: ' + str(nrow[0][6]) + '\nSource Address: ' + str(nrow[0][7]) + ' Destination Address: ' + str(nrow[0][8])
        print str(nrow[1])
        print "Data: " + nrow[2].decode('utf-8', 'ignore') + '\n\n\n'

def main(argv):
	global interface, detail
	interface='enp0s3'
	devices=pcapy.findalldevs()   #Find all network interfaces
	detail=''
	sniffme()
if __name__ == "__main__":
  main(sys.argv)
