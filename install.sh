mkdir PTO
cd PTO
apt-get install python-mysqldb
pip install pymetasploit
wget https://raw.githubusercontent.com/FurqanKhan1/Dictator/master/nmapscan.sql
git clone https://github.com/FurqanKhan1/Dictator.git
git clone https://github.com/FurqanKhan1/Dictator_client.git
apt-get install mdns-scan
pip install python-nmap
pip install python-libnmap
pip install python-libnessus
pip install lxml
pip install psutil
pip install django==1.11.10
pip install djangorestframework==3.7.7
pip install markdown       # Markdown support for the browsable API.
pip install django-filter  # Filtering support
sudo apt-get install python-mysqldb
apt-get install python-magic
pip install texttable
pip install pyshark==0.3.8
pip install ansi2html
cd dictator_service/Dictator_service/Scripts/hoppy-1.8.1/hoppy-1.8.1-
sudo make install
cd ..
git clone https://github.com/EnableSecurity/sipvicious.git
cd sipvicious
python setup.py install
cd ..
service mysql stop
apt-get --purge remove 'mysql*'
mkdir mysql_install
cd mysql_install
wget https://dev.mysql.com/get/Downloads/mysql/mysql-server_5.7.17-1debian7_amd64.deb-bundle.tar
tar -xvf mysql-server_5.7.17-1debian7_amd64.deb-bundle.tar
sudo dpkg-preconfigure mysql-community-server_*.deb
sudo dpkg -i mysql-{common,community-client,client,community-server,server}_*.deb
sudo apt-get -f install
#sudo apt-get update
cd ..
mysql -p  < nmapscan.sql
