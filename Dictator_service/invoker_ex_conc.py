"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to launch discovery process with gui mode and concurrency .
Invoker_ex_conc.py is actually responsible for calling driver_meta.py along with project_id and relevent 
switches  in concurrent mode which shall make the code driver_meta.py to run in execute mode and it will start vul scan.
A process will keep on running in the background which shall do the scanning and save the details in
the database table.
"""


import driver_meta as driver_exploits
import os
import ConfigParser
import time
import psutil
import subprocess
import sys
import threading
import ast

DriverObj=driver_exploits.Driver()

project_id=sys.argv[1]
continue_=sys.argv[2]
delete=sys.argv[3]
get_default_config=sys.argv[4]
threading_=sys.argv[5]
concurrent=sys.argv[6]
records=sys.argv[7]
#rec_list=map(str,records.strip('[]').split(','))
rec_list=ast.literal_eval(records)



print "Inside Invoker_ex_conf.py \n\n"
print "Recieved aurguments are :"
print(project_id,continue_,delete,get_default_config,threading_,concurrent,str(rec_list),str(records))
active_threads=threading.enumerate()
counter=len(active_threads)
print "Inside invoker_ex.The number of threads active  are :"+str(active_threads)+"\n"

DriverObj.main('gui',project_id,True,False,False,False,True,rec_list,True) 
#(self,mode='c',project_id_='',continue_=False,delete=False,get_updated_config=False,threading_=False,concurrent=False,record_list=[],skip_init_check=False)



