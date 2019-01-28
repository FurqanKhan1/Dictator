# What is PTO (Penetration Testing Orchestrator) ? :#
PTO  is a network penetration testing automation tool that automates port discovery and service scanning phases of penetration testing 

1.      Discovery (Port Scanning) -Nmap
2.  	Vulnerability Scanning (Service Scanning) -Metasploit ,Terminal automation ,nse ,open source (python ,ruby ,shell ,nse ,perl) scripts ,Kali Linux Built in tools.
3. 	PTO is developed in python and django and uses mysql at backend.
	
# Target Users #

1.   PTO will be useful for penetration testers as it automates most of the manual activities that penetration testers engage in  during testing. .

2.   On top of automation PTO improves performance of Penetration Testing by making use of thread parallelism for both port discovery and service scanning .

3. PTO is flexible and extendable : As of now PTO has automated 206 test cases of service scanning .The architecture adapted to design PTO is extendable i.e. without making change at code level ,we can add more external scripts /test cases /Metasploit models with PTO ,by just changing the settings file.

4. PTO comes in various modes of Operations for conducting Scan : 
    (a) Sequential Scan Mode
    (b) Concurrent Scan Mode
    (c) Sequential-Default Scan Mode.

# DISCLAIMER: #
"DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE." 

# INSTALLATION STEPS : #
       Pull the code For PTO as follows :
             Pull/Clone code of dictator_service  : git clone <url>
             Pull /Clone code of dictator_client  : git clone <url>
             Downloading database nmapscan.sql     :The database is present at the root directory of Dictator Code base

# OTHER DEPENDENCIES : #

# Dependencies from Internet /Web: #

Either install them manually by typing each command in terminal

	apt-get install mdns-scan
	pip install python-nmap
	pip install python-libnmap
	pip install python-libnessus
	pip install lxml
	pip install django
	pip install djangorestframework
	pip install markdown       # Markdown support for the browsable API.
	pip install django-filter  # Filtering support
	sudo apt-get install python-mysqldb
	apt-get install python-magic
	pip install texttable
	pip install pyshark
	pip install ansi2html

Alternatively the above mentioned installables are also present in this shell script which can be run as :
	sudo sh install.sh



The following steps need to be performed maunally :


## Perl Dependencies  : ##

	Open cpan by typing following command :
	cpan

	Type following commands 
		install XML::Simple
		install Encoding::BER

## External Tool Dependencies : ##
	Installing Hoppy:
		Assuming you have downloaded dictator_service from git , go to the following path -
		cd dictator_service/Dictator_service/Scripts/hoppy-1.8.1/hoppy-1.8.1-
			Type-
				sudo make install

       Install Spvicious :
		 git clone https://github.com/EnableSecurity/sipvicious.git
		 cd sipvicious
		 python setup.py install



## Installing Mysql ##

	If you are using ubuntu 14.04,16.04,linux wheezy ,jheezy then follow the following :

		wget https://dev.mysql.com/get/mysql-apt-config_0.8.3-1_all.deb
		sudo dpkg -i mysql-apt-config_w.x.y-z_all.deb
		sudo apt-get update
		Link to refer :https://dev.mysql.com/doc/mysql-apt-repo-quick-guide/en/#repo-qg-apt-upgrading

	If it is any other version of debian ,than the preferred way of installation is from the development packages 
		Tested on Kali-roling (5.7.15):

		Download the deb bundle DEB Bundle 5.7.*  https://dev.mysql.com/downloads/mysql/
		(mysql-server_5.7.17-1debian7_amd64.deb-bundle.tar)

		After download follow these steps :
			tar -xvf mysql-server_MVER-DVER_CPU.deb-bundle.tar
			sudo apt-get install libaio1
			sudo dpkg-preconfigure mysql-community-server_*.deb
			sudo dpkg -i mysql-{common,community-client,client,community-server,server}_*.deb
			sudo apt-get -f install

		Alternatively you may reffer to following URL :
			https://dev.mysql.com/doc/refman/5.7/en/linux-installation-debian.htm



## Getting STARTED : ##

First create following databases :
 mysql -u <user_name> -p <password>
	create database nmapscan;
	create dictator_client;
	exit;

Restoring the Web service /API databse :
	mysql -p  nmapscan < nmapscan.sql 


### Setting Database Password for Client /Web application <dictator_client>  : ###
	Go to the path where your dictator_client would be and make sure you have current db username and password in settings.py file 
	</dictator_client/Dictator_client/settings.py>

	Under the entry DATABASES { 

		'NAME': 'dictator_client',
        	'USER': 'sql user',
        	'PASSWORD': 'mysql password',
        
				}
## Setting Database Password for Dictator Service -Web Service : ##
	 Open the text file at the path : cd dictator_service/Dictator_service/db_file.txt
	 The text file would be having dummy <username:password> for your mysql database .
	 Update the username password from root:toor_pw to <your_username>:<your_password>

## Sync Web application Database tables : ##
	cd dictator_client 
	Then create database tables for client application by running following command :
	python manage.py makemigrations
	python manage.py migrate


## Running Dictator_client : ##

To get Started Create an admin /Superuser .This user will be Having Role admin at Django administration .
But with application ,it will be having role of normal user.
	
	python manage.py createsuperuser
	provide username ,password ,email etc.
	Finally run the web application by using the command 
	python manage.py runserver 8000
	Then browse to http://127.0.0.1:8000/admin 

	Add users to user table and and same user would be added to profile table where you can go and change the user role 
	By default the role would be "user" with normal privileges and other role would be "admin" with admin privileges.
	
	Admin user has more privileges and can view /pause /resume scans of all users.



## Running Dictator_service : ##

	To get started with Dictator service :

	Issue following command :python manage.py runserver 8002 #8002 as the web service /API consumer expects the service to be served on port 8002



