mkdir PTO
cd PTO
wget https://raw.githubusercontent.com/FurqanKhan1/Dictator/master/nmapscan.sql
git clone https://github.com/FurqanKhan1/Dictator.git
git clone https://github.com/FurqanKhan1/Dictator_client.git
apt-get install mdns-scan
pip install python-nmap
pip install python-libnmap
pip install python-libnessus
pip install lxml
pip install django==1.11.10
pip install djangorestframework==3.7.7
pip install markdown       # Markdown support for the browsable API.
pip install django-filter  # Filtering support
sudo apt-get install python-mysqldb
apt-get install python-magic
pip install texttable
pip install pyshark
pip install ansi2html
cd dictator_service/Dictator_service/Scripts/hoppy-1.8.1/hoppy-1.8.1-
sudo make install
cd ..
git clone https://github.com/EnableSecurity/sipvicious.git
cd sipvicious
python setup.py install
cd ..
wget https://dev.mysql.com/get/mysql-apt-config_0.8.3-1_all.deb
sudo dpkg -i mysql-apt-config_w.x.y-z_all.deb
sudo apt-get update
mysql -p  < nmapscan.sql
