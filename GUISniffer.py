from Tkinter import *   
from struct import *
from impacket import ImpactDecoder, ImpactPacket
import socket
import Pmw
import pcapy
import thread
import sys
import tkMessageBox

primary='#9b26af'
accent='#68efad'
primarydark='#691a99'
interface=''
detail=''
table=''
protocols={6:"TCP", 1: "ICMP", 17: "UDP"}

class SimpleTable(Frame):
    def __init__(self, parent, bg, fg, clearbackground, columns):
        Frame.__init__(self, parent, background=clearbackground, relief=FLAT)
        self._widgets = []
        self.bg = bg
        self.fg = fg
        current_row = []
        for column in columns:
            label = Label(self, text="%s" % (column), borderwidth=1, fg=fg, relief=FLAT)
            label.grid(row=0, column=columns.index(column), sticky=W+E+N+S, ipadx=3, ipady=1, padx=1, pady=1)
            current_row.append(label)
        self._widgets.append(current_row)
        for column in columns:
            self.grid_columnconfigure(columns.index(column), weight=1)

    def showdetails(self, arg):
		global detail
		detail.set(arg['details'] + '\nData: ' + arg['data'].decode('utf-8', 'ignore'))
		for row in self._widgets:
			if row[0] != self._widgets[0][0]:
				for label in row:
					label.config(bg='white')
		if len(self._widgets) > arg['row']:
			for label in self._widgets[arg['row']]:
				label.config(bg='#eeeeee')

    def insert(self, nrow):
		new_row=[]
		bg=self.bg
		fg=self.fg
		values=nrow[0]
		for value in values:
			label = Label(self, text="%s" % (value), borderwidth=0, bg=bg, fg=fg, relief=FLAT)
			label.grid(row=len(self._widgets), column=values.index(value), sticky=W+E, ipadx=3, ipady=1, padx=(0,1), pady=(1,0))
			data = {"details": nrow[1], "row": len(self._widgets), "data": nrow[2]}
			label.bind('<Button-1>', lambda e, arg=data: self.showdetails(arg))
			new_row.append(label)
		self._widgets.append(new_row)

    def set(self, row, column, value):
        widget = self._widgets[row][column]
        widget.configure(text=value)

def sniffme():
	global interface
	cap = pcapy.open_live(interface.get() , 65536 , 1 , 0)
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
    global table, protocols
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
        table.insert(nrow)

def threadone():
	try:
		thread.start_new_thread(sniffme,())
	except (KeyboardInterrupt, SystemExit):
		cleanup_stop_thread();
		sys.exit()

def main(argv):
	global primary, accent, interface, primarydark, detail, table
	root = Tk()
	interface=StringVar()
	root.minsize(1000,500)
	root.title("Packet sniffer")
	img = PhotoImage(file='sniffer.png')
	root.tk.call('wm', 'iconphoto', root._w, img)
	root.configure(background='white')
	#Toolbar
	fm = Frame(root, bg=primary, relief=RAISED)
	Button(fm, text='Start Capture', bg=accent, fg='white', height=2, relief=RAISED, command=threadone, activebackground=accent, activeforeground='white').pack(side=RIGHT,anchor=NE,pady=(15,0),padx=(0,20),expand=NO)
	Label(fm, text='Packet Sniffer', bg=primary, fg='white', font=('Helvetica', 16)).pack(side=TOP,pady=(5,0))
	Label(fm, text='v1.0', bg=primary, fg='white', font=('Helvetica', 10)).pack(side=TOP)
	
	fm.pack(side=TOP, expand=NO, fill=X)
	#Toolbar end
	#Interface radio buttons
	devices=pcapy.findalldevs()   #Find all network interfaces
	rf = Frame(root, bg=primary)
	for d in devices:
		Radiobutton(rf, text=d, variable=interface, value=d, bg=primary, fg='white', selectcolor=primarydark, activebackground=primarydark, highlightbackground=primary, activeforeground='white').pack(side=LEFT,padx=0, ipadx=30, ipady=5, anchor=W, expand=YES)
	interface.set(devices[0])
	rf.pack(side=TOP,expand=NO,fill=X)
	#radio buttons end
	#Packets table
	bsf=Pmw.ScrolledFrame(root, horizflex='expand', borderframe=0)
	bsf.pack(side=TOP,fill=X, expand=NO)
	vscrollbar=bsf.component('vertscrollbar')
	hscrollbar=bsf.component('horizscrollbar')
	clipper=bsf.component('clipper')
	clipper.configure(relief=FLAT, borderwidth=0, height=275)
	vscrollbar.config(bg=accent, troughcolor='white', activebackground=accent, relief=FLAT, borderwidth=1)
	hscrollbar.config(bg=accent, troughcolor='white', activebackground=accent, relief=FLAT, borderwidth=1)
	bf=bsf.interior()
	bf.configure(bg='white', relief=FLAT)
	columns=['Destination MAC','Source MAC', 'Protocol', 'Version', 'IP HLen', 'TTL', 'IP Protocol', 'Source Address', 'Destination Address' ]
	table=SimpleTable(bf,'white', 'black', 'black',columns)
	table.pack(side=TOP, fill=BOTH)
	#Packets table end
	#Detail section
	detsf=Pmw.ScrolledFrame(root, horizflex='expand')
	detsf.pack(side=TOP,fill=BOTH, expand=YES)
	detsf.component('clipper').configure(relief=FLAT, borderwidth=0, bg='white')
	detsf.component('vertscrollbar').config(bg=accent, troughcolor='white', activebackground=accent, relief=FLAT, borderwidth=1)
	detsf.component('horizscrollbar').config(bg=accent, troughcolor='white', activebackground=accent, relief=FLAT, borderwidth=1)
	detf=detsf.interior()
	detail=StringVar()
	Label(detf, textvariable=detail, fg='black', bg='white',font=('Helvetica')).pack(side=BOTTOM, anchor=W, fill=X)
	detail.set("Click on a packet to see details")
	#Detail section end
	root.mainloop()
if __name__ == "__main__":
  main(sys.argv)
