"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to aid in HTML report generation.The html report has got a defined template containing of custom headers and body sections for neessus ,mannual and qualys subsections
of the report.This file contains the various methods that return the html template blended with teh report content.The reason for providing a seperate class for same is code reusibility

"""
import Report_Generator
import datetime
class Html_template:
	"""
	
		Objective :
		This class has various methods to invoke bland and return the HTML report template for mannual,
		qualys and nessus sub sections of the report
	"""

	def get_header(self,host):
		"""
		Objective :
		This method will return the header section of the HTML report blended with the Host for which the 
		section gives information about.
		"""
		return "<div  class=row style='border-style:solid;border-width:thin;border-color:#34495E;Background-color:#FFF'><div class=' col-sm-12 alert alert-info' style='background-color:#34495E;color:white;background-image:url(bk/background_blue.JPG)'><h4><span class='glyphicon glyphicon-th-large'></span>&nbsp;HOST : <a href=#  style='text-decoration:none;color:white'>"+host+"</a></h4></div>"


	def get_host_wrap(self,counter):
		"""
		Objective :
		This method will return host div which shall wrap all host and services content.
		"""

		return "<div class=col-sm-12 id=host_"+str(counter)+ " style='display:block;)'>"


	def get_init_table(self,s_counter,host,port,service):
		"""
		Objective :
		This method will return the display HTML table which shall contain the discovered host
		and port and service.
		"""

		return "<br><div><a href=#service_"+str(s_counter)+ " data-toggle=collapse><span class='glyphicon glyphicon-list'></span>&nbsp;&nbsp;"+str(service)+"</a><br></div><div class=collapse id=service_"+str(s_counter)+"><br><table class='table table-condensed' style='background-image:url(bk/background_light.JPG);border-left:1px solid #000000;'><tr><td>Host</td><td>Port</td><td>Service</td><tr><tr><td>"+str(host)+"</td><td>"+str(port)+"</td><td>"+str(service)+"</td></tr></table>"

	
	def get_init_table_add(self,s_counter,host,message):
		"""
		Objective :
		This method will return the display HTML table for additional services /hosts discoverd by 
		nessus or qualys
		"""

		return "<br><div><a href=#service_"+str(s_counter)+ " data-toggle=collapse><span class='glyphicon glyphicon-list'></span>&nbsp;&nbsp;"+message+"</a><br></div><div class=collapse id=service_"+str(s_counter)+"><br><table class='table table-condensed' style='background-image:url(bk/background_light.JPG);border-left:1px solid #000000;'><tr><td>Host</td><td>Info</td><tr><tr  style='font-family:arial;font-size:14px'><td>"+str(host)+"</td><td>Some additional findings are given as under</td></tr></table>"

	def get_exploit_template(self,exploits_,template_message):
		"""
		Objective :
		This method will return the display content in a div which shall contain outer template for all 		mannual test cases and their results
		"""

		return "<div class=exploit_header ><a href=#exploits_"+str(exploits_)+" data-toggle=collapse><font color =red><span class='glyphicon glyphicon-list'></span>&nbsp;<b>"+template_message+"</b> </font></a><br></div><div id=exploits_"+str(exploits_)+" 'style=display:none;' class=collapse><br><br><div class=exploits_result>"

	def get_command_template(self,command_id):
		"""
		Objective :
		This method will return the display content in a div which shall display the mannual command that
		would be executed
		"""

		return "<b> <font color=green><span class='glyphicon glyphicon-info-sign'></span>&nbsp;Command Id : "+str(command_id)+"</font></b><br><br>"

	def get_nessus_header(self,host,port,os,protocol,service):
		"""
		Objective :
		This method will return the display content in a div which shall contain the HTML header for nessus
		discovered services
		"""

		table="<div><br><table class='table'>\
			<tr style ='background-image:url(bk/bg_voilet_1.JPG);color:white'><td>&nbsp;Host</td><td>Port</td><td>Service</td><td>Protocol&nbsp;</td></tr>\
			<tr><td>"+host+"</td><td>"+port+"</td><td>"+service+"</td><td>"+protocol+"</td></tr>\
			</table><br></div>"
			
		return table +""

	def get_qualys_header(self,host,port):
		"""
		Objective :
		This method will return the display content in a div which shall contain the HTML header for qualys
		discovered services
		"""

		table="<div><br><table class='table'>\
			<tr style='background-image:url(bk/bg_voilet_1.JPG);color:white'><td>Host</td><td>Port</td></tr>\
			<tr><td>"+host+"</td><td>"+port+"</td></tr></table><br></div>"
			
		return table +"<br>"

	def get_nessus_body(self,plugin_id,plugin_name,severity,synopsis,description,ref,exploits,risk_vec,solution,port):
		"""
		Objective :
		This method will return the display content in a div which shall contain the HTML body for nessus
		discovered services and the results .
		"""

		obj=Report_Generator.ReportGenerator()
		ref_list=obj.getExploits(ref,True)
		reff=''
		expl=''
		if len(ref_list) >0:
			reff="<ul>"
			for r in ref_list:
				reff=reff+"<li>"+str(r)+"</li>"
			reff=reff+"</ul>"
		if len(exploits)>0:
			expl="<ul>"
			for e in exploits:
				expl=expl+"<li>"+str(e)+"</li>"
			expl=expl+"</ul>"

		stripped_severity=str(severity.strip())
		bk='url(bk/background_yellow.JPG)'
		color="black"
		if stripped_severity=="" or stripped_severity=="0":
			bk='url(bk/bg_green.JPG)'
		elif stripped_severity=="1" :
			bk='url(bk/bg_voilet_3.JPG)'
			color="white"
		elif stripped_severity=="2":
			bk='url(bk/bg_blue.JPG)'
		elif stripped_severity=="3":
			bk='url(bk/background_yellow.JPG)'
		elif stripped_severity=="4":
			bk='url(bk/bg_orange.JPG)'
		elif stripped_severity=="5":
			bk='url(bk/bg_red.JPG)'

		table="<div><br><table class='table' style='border-left:1px solid #000000;background-image:url(bk/background_light.JPG);table-layout:fixed'>\
			<tr><td>\
			<table class='table'>\
			<tr align=center style ='background-image:"+bk+";color:"+color+"'><td>&nbsp;Plugin Id</td><td>Plugin Name</td><td>Sevirity&nbsp;</td></tr>\
			<tr align=center><td>"+plugin_id+"</td><td>"+plugin_name+"</td><td>"+severity+"</td></tr>\
			</table>\
			</td></tr>\
			<tr><td>\
			<table class='table'>\
			<tr align =center style ='background-image:"+bk+";color:"+color+"'><td>&nbsp;Description</td><td>Synopsis&nbsp;</td><td>Solution</td></tr><tr><td><br></td></tr>\
			<tr align='center' style='font-family:arial;font-size:14px;word-break:break-all'><td>"+description+"</td><td>"+synopsis+"</td><td>"+solution+"</td></tr>\
			<tr><td><br></td></tr>\
			<tr align='center' style ='background-image:"+bk+";color:"+color+"'><td>&nbsp;RISK Vectors</td><td>REFERENCES</td><td>Exploits&nbsp;</td></tr><tr><td><br></td></tr>\
			<tr align='center' style='font-family:arial;font-size:15px;font-weight:bold'><td>"+str(risk_vec)+"</td><td>"+str(reff)+"</td><td>"+expl+"</td></tr>\
			</table>\
			</td></tr>\
			</table><br></div>"
		return table

	def get_qualys_body(self,severity,title,cvss,protocol,result,diagnosis,ref,exploits,sub_type,solution,port):
		"""
		Objective :
		This method will return the display content in a div which shall contain the HTML body for qualys
		discovered services and the results .
		"""

		obj=Report_Generator.ReportGenerator()
		ref_list=ref
		reff=''
		expl=''
		if len(ref_list) >0:
			reff="<ul>"
			for r in ref_list:
				reff=reff+"<li>"+str(r)+"</li>"
			reff=reff+"</ul>"
		if len(exploits)>0:
			expl="<ul>"
			for e in exploits:
				expl=expl+"<li>"+str(e)+"</li>"
			expl=expl+"</ul>"

		stripped_severity=str(severity.strip())
		bk='url(bk/background_yellow.JPG)'
		color="black"
		if stripped_severity=="" or stripped_severity=="0":
			bk='url(bk/bg_green.JPG)'
		elif stripped_severity=="1" :
			bk='url(bk/bg_voilet_3.JPG)'
			color="white"
		elif stripped_severity=="2":
			bk='url(bk/bg_blue.JPG)'
		elif stripped_severity=="3":
			bk='url(bk/background_yellow.JPG)'
		elif stripped_severity=="4":
			bk='url(bk/bg_orange.JPG)'
		elif stripped_severity=="5":
			bk='url(bk/bg_red.JPG)'


		table="<div><br><table class='table' style='border-left:1px solid #000000;background-image:url(bk/background_light.JPG);table-layout:fixed'>\
			<tr><td>\
			<table class='table'>\
			<tr align=center style ='background-image:"+bk+";color:"+color+"'><td>&nbsp;Title</td><td>Port</td><td>Sevirity&nbsp;</td></tr>\
			<tr align=center><td>"+title+"</td><td>"+port+"</td><td>"+severity+"</td></tr>\
			</table>\
			</td></tr>\
			<tr><td>\
			<table class='table' style='table-layout:fixed'>\
			<tr align=center style ='background-image:"+bk+";color:"+color+";word-break:break-all'><td>&nbsp;Result</td><td>Diagnosis&nbsp;</td><td>Solution</td></tr><tr><td><br></td></tr>\
			<tr align='center' style='font-family:arial;font-size:15px;word-break:break-all'><td>"+result+"</td><td>"+diagnosis+"</td><td>"+solution+"</td></tr>\
			<tr><td><br></td></tr>\
			<tr align=center style ='background-image:"+bk+";color:"+color+"'><td>&nbsp;CVSS</td><td>REFERENCES</td><td>Exploits&nbsp;</td></tr><tr><td><br></td></tr>\
			<tr align='center' style='font-family:arial;font-size:15px;font-weight:bold'><td>"+str(cvss)+"</td><td>"+str(reff)+"</td><td>"+expl+"</td></tr>\
			</table>\
			</td></tr>\
			</table><br></div>"
		return table


	def get_exploit_body_commands(self,commands):
		"""
		Objective :
		This method will return the display content in a div which shall contain the HTML body for mannual
		discovered services and the results .
		"""

		return "<div style=background-color:black;color:white>Command :<br>"+str(commands).replace("<","&lt").replace(">","&gt").replace('\n','<br>').replace('\r','<br>').replace('\r\n','').replace('\r\r','<br>')+"</div><br>"

	def get_exploit_body_results(self,result):
		return "<div style=background-color:black;color:white>Results : <br>"+str(result.replace("<","&lt").replace(">","&gt")).replace('\n','<br>').replace('\r','<br>').replace('\r\n','').replace('\r\r','<br>') +"</div><br>"

	def close_divs_item(self):
		return "</div></div><br>"
		#return "</div></div></div><br>"

	def close_parents(self):
		return "</div></div><div class=row style='background-color:#f1f1f1'><div class='col-sm-12'><br></div></div>"

	def get_header_bs(self):
		"""
		Objective :
		This method will return the display content in a div which shall contain the web page Header.
		The menu and the relevent bootstrap and jquery file links
		"""

		return '''<head>  			
  			<meta charset="utf-8">
  			<meta name="viewport" content="width=device-width, initial-scale=1">
			<link href="bootstrap/css/bootstrap.min.css" rel="stylesheet">
  			<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
			<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
  			<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
			<script src="bootstrap/js/jquery.js"></script>
			<script src="bootstrap/js/bootstrap.min.js"></script>
			<script type='text/javascript'>
			
$(document).ready(function(){ 
	//alert('hello world'); 
$('.collapse').on('shown.bs.collapse', function(){
//alert('bye');
$(this).parent().find(".glyphicon-plus").removeClass("glyphicon-plus").addClass("glyphicon-minus");
}).on('hidden.bs.collapse', function(){
$(this).parent().find(".glyphicon-minus").removeClass("glyphicon-minus").addClass("glyphicon-plus");
});	
});		</script>
			</head>'''

	def get_nav_bar(self):
		"""
		Objective :
		This method will return the dynamically created bootstrap navigation/menu bar placed at 
		top of web page.
		"""

		return '''<nav class="navbar navbar-inverse navbar-fixed-top" style='background-image:url(bk/background_black.JPG)'>
  <div class="container-fluid">
    <div class="navbar-header">
      <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#myNavbar">
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span> 
      </button>
     <p><a class="navbar-brand glyphicon glyphicon-king" style='color:red;position:relative;left:20%'><font color=red>-DICTATOR</font></a></p>
    </div>
    <div class="collapse navbar-collapse" id="myNavbar">
      <ul class="nav navbar-nav" style=position:relative;left:3%>
	
        <li class="acstive"><a href="#">Scan Report</a></li>

      </ul>
      <ul class="nav navbar-nav navbar-right">
        <li><a href="#"><span class="glyphicon glyphicon-user"></span> Sign Up</a></li>
        <li><a href="#"><span class="glyphicon glyphicon-log-in"></span> Login</a></li>
      </ul>
    </div>
  </div>
</nav>'''
			
			
					
	def get_html_body(self,bootstrap,nav_bar,service_counter,all_exploits):
		"""
		Objective :
		This method will gather al;l the pieces to geather and would place the page header and page body at
		appropriate places to return the finally created web page.
		"""

		return "<html><title>Nmap Scanning Result</title>"+bootstrap+"\
		<body>\
		<div class='container-fluid' style=background-color:#f1f1f1>"+nav_bar+"<br><br><br>\
		<div class=col-sm-2 >\
			<div class=row>\
				<div class='col-sm-12'>\
					<div class='col-sm-12' style='background-color:#6B8E23;color:white;text-align: \
					center;'><h5><span class='glyphicon glyphicon-record'></span>&nbsp;Scan Summery\
					</h5>\
					</div>\
					<div style=border-style:solid;border-width:thin;background-color:white>\
						<br><medium><font color=black><b>&nbsp;<span class='glyphicon glyphicon-ok-sign'\
					 	style=color:#6B8E23></span>&nbsp; Date :"+str(datetime.datetime.now())[0:16]+"<br>\
					 	&nbsp;<span class='glyphicon glyphicon-ok-sign' style=color:#6B8E23></span>&nbsp;\
					 	Hosts : "+str(service_counter)+"<br>&nbsp;<span class='glyphicon glyphicon-ok-sign'\
					 	style=color:#6B8E23></span>&nbsp; Test Cases : "+str(all_exploits)+"<br></b></font>\
						</medium>\
					</div>\
					<br>\
					<div class='col-sm-12' style='background-color:#6B8E23;color:white;text-align:\
					 center;'><h5><span class='glyphicon glyphicon-record'></span>&nbsp;Disclaimer</h5>\
					</div>\
					<div style=border-style:solid;border-width:thin;background-\
						color:white><br><br><small><font color=red><ul class=list-group>\
						<li class=list-group-item><span class='glyphicon glyphicon-info-sign'></span>&nbsp;The scan results are\
					 	subjected to Nmap's accurecy of determining open ports and avalible services.\
						</li><li\
					 	class=list-group-item><span class='glyphicon glyphicon-info-sign'></span>&nbsp;Nmap\
					 	works on convention over exploration.If a well known port say 1433 is open,nmap \
						assumes sql-server to be running on it,evn if some other service would be running.\
						</li><li class=list-group-item><span class='glyphicon glyphicon-info-sign'>\
						</span>&nbsp;It is adviced that if the produced exploit results are strange \
						,then one must manually check for the service running on the port</li></ul></font>\
						</small>\
					</div>\
				</div>\
			</div>\
		</div>\
		<div class=col-sm-10 style=background-color:white>"

