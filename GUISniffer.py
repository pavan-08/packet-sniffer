from Tkinter import *   
from pcapy import findalldevs,open_live
from impacket import ImpactDecoder, ImpactPacket
import thread
import sys
import tkMessageBox

primary='#9b26af'
accent='#68efad'

def main(argv):
	global primary, accent
	root = Tk()
	root.minsize(1000,500)
	root.title("Packet sniffer")
	img = PhotoImage(file='sniffer.png')
	root.tk.call('wm', 'iconphoto', root._w, img)
	root.configure(background='white')
	fm = Frame(root, bg=primary)
	Label(fm, text='Packet Sniffer', bg=primary, fg='white', font=('Helvetica', 16)).pack(side=TOP,pady=(5,0))
	Label(fm, text='v1.0', bg=primary, fg='white', font=('Helvetica', 10)).pack(side=TOP)
	fm.pack(side=TOP, expand=NO, fill=X)
	root.mainloop()

if __name__ == "__main__":
  main(sys.argv)
