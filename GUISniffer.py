from Tkinter import *   
import Pmw
import pcapy
from impacket import ImpactDecoder, ImpactPacket
import thread
import sys
import tkMessageBox

primary='#9b26af'
accent='#68efad'
primarydark='#691a99'
interface=''
detail=''

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
		detail.set(arg['details'])
		for row in self._widgets:
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
			data = {"details": nrow[1], "row": len(self._widgets)}
			label.bind('<Button-1>', lambda e, arg=data: self.showdetails(arg))
			new_row.append(label)
		self._widgets.append(new_row)

    def set(self, row, column, value):
        widget = self._widgets[row][column]
        widget.configure(text=value)


def canvasfunc(event):
	canvas.configure(scrollregion=canvas.bbox("all"),width=200,height=200)

def main(argv):
	global primary, accent, interface, primarydark,detail
	root = Tk()
	interface=StringVar()
	root.minsize(1000,500)
	root.title("Packet sniffer")
	img = PhotoImage(file='sniffer.png')
	root.tk.call('wm', 'iconphoto', root._w, img)
	root.configure(background='white')
	#Toolbar
	fm = Frame(root, bg=primary, relief=RAISED)
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
	######sample data begin
	values=['08:00:27:a2:be:63','0c:d2:b5:2c:d7:c4', '8', '4', '5', '55', '1', '216.58.197.68', '192.168.1.101']
	details='Type : 0 Code : 0 Checksum : 59306 Data : !"#$%&\'()*+,-./01234567'	
	nrow=[]
	nrow.append(values)
	nrow.append(details)
	table.insert(nrow)
	values=['08:00:27:a2:be:63','0c:d2:b5:2c:d7:c4', '8', '4', '5', '55', '1', '216.58.197.68', '192.168.1.101']
	details='Type : 0 Code : 0 Checksum : 5930123 Data : !"#$%&\'()*+,-./01234567'	
	nrow=[]
	nrow.append(values)
	nrow.append(details)
	table.insert(nrow)
	##########sample data end
	#Detail section
	detsf=Pmw.ScrolledFrame(root, horizflex='expand')
	detsf.pack(side=TOP,fill=BOTH, expand=YES)
	detsf.component('clipper').configure(relief=FLAT, borderwidth=0, bg='white')
	detsf.component('vertscrollbar').config(bg=accent, troughcolor='white', activebackground=accent, relief=FLAT, borderwidth=1)
	detf=detsf.interior()
	detail=StringVar()
	Label(detf, textvariable=detail, fg='black', bg='white',font=('Helvetica')).pack(side=BOTTOM, anchor=W, fill=X)
	detail.set("Click on a packet to see details")
	#Detail section end
	root.mainloop()
if __name__ == "__main__":
  main(sys.argv)
