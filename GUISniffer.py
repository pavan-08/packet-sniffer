from Tkinter import *   
import pcapy
from impacket import ImpactDecoder, ImpactPacket
import thread
import sys
import tkMessageBox

primary='#9b26af'
accent='#68efad'
primarydark='#691a99'
interface=''
def main(argv):
	global primary, accent, interface, primarydark
	root = Tk()
	interface=StringVar()
	root.minsize(1000,500)
	root.title("Packet sniffer")
	img = PhotoImage(file='sniffer.png')
	root.tk.call('wm', 'iconphoto', root._w, img)
	root.configure(background='white')
	fm = Frame(root, bg=primary)
	Label(fm, text='Packet Sniffer', bg=primary, fg='white', font=('Helvetica', 16)).pack(side=TOP,pady=(5,0))
	Label(fm, text='v1.0', bg=primary, fg='white', font=('Helvetica', 10)).pack(side=TOP)
	fm.pack(side=TOP, expand=NO, fill=X)
	devices=pcapy.findalldevs()   #Find all network interfaces
	rf = Frame(root, bg=primary)
	for d in devices:
		Radiobutton(rf, text=d, variable=interface, value=d, bg=primary, fg='white', selectcolor=primarydark, activebackground=primarydark, highlightbackground=primary, activeforeground='white').pack(side=LEFT,padx=0, ipadx=30, ipady=5, anchor=W, expand=YES)
	interface.set(devices[0])
	rf.pack(side=TOP,expand=NO,fill=X)
	bf = Frame(root, bg='white')
	scrollbar=Scrollbar(bf)
	scrollbar.config(bg=accent, troughcolor='white', highlightbackground=primary, relief=RIDGE)
	scrollbar.pack(side=RIGHT, fill=Y)
	bf.pack(side=TOP,expand=YES,fill=BOTH)
	root.mainloop()
if __name__ == "__main__":
  main(sys.argv)
