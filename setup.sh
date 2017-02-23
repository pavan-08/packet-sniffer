sudo apt-get install -y python-pip
sudo apt-get install -y python-tk
sudo apt-get install -y libpcap0.8-dev
#lib folder
mkdir lib
cd lib
#downloading pcapy impacket and pmw
wget 'https://pypi.python.org/packages/7f/12/626c6c1ee949b6d447f887a65388aa83faec6feb247e1bdf2478139a6078/pcapy-0.11.1.tar.gz'
wget 'https://pypi.python.org/packages/35/72/694c391c7fe29600c2c8d8d4aa97a781562c39bb66a3d20bbee9858ca698/impacket-0.9.15.tar.gz'
wget 'https://excellmedia.dl.sourceforge.net/project/pmw/Pmw-2.0.0.tar.gz'
#Unzipping packages
pwd
ls
tar -xvzf 'pcapy-0.11.1.tar.gz'
tar -xvzf 'impacket-0.9.15.tar.gz'
tar -xvzf 'Pmw-2.0.0.tar.gz'
#installing all libs, requires root
cd pcapy-0.11.1
sudo python setup.py install
cd ..
cd impacket-0.9.15
sudo python setup.py install
cd ..
cd Pmw-2.0.0
sudo python setup.py install
cd ..
if [ "$?" -eq "0" ]
then
	echo '----------------------------------------------------'
	echo 'The libraries have been successfully installed'
	echo '----------------------------------------------------'
fi
