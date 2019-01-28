"""
@Author		:Furqan Khan
@Email		:furqankhan08@gmail.com
@Date 		:1/2/2017

Objective :
The purpose of this file /module /Class is to map the urls with the views(In django controllors are called as views)
The views would actually have the methods (get, post,delete,put ) which are meant to be executed
when a user/application requests for a rest service url.

Dictator URL Configuration

Thus when a user will request for a url like [host ip]:port/scan 
The control will go to the get or post method of class StartScan which is a part of Views class.
Weather teh get or post method would execute it would depend upon the request type forwarded.

The mapped urls are given as under :

urlpatterns = [
    url(r'^admin/', admin.site.urls),
	url(r'^users/', views.UserList.as_view()),
	url(r'^csrf/', views.SetCsrf.as_view()),
	url(r'^scan/', views.StartScan.as_view()),
	url(r'^scan_concurrent/', views.StartScanConcurrent.as_view()),
	url(r'^polling/', views.PollingConfig.as_view()), #polling in concurrent mode
	url(r'^percentPolling/', views.PercentPolling.as_view()),
	url(r'^polling_scanning/', views.PollingExploit.as_view()),
	url(r'^stop/', views.StopScan.as_view()),
	url(r'^stop_conc/', views.StopScanConc.as_view()),
	url(r'^stop_scanning/', views.StopExploits.as_view()),
	url(r'^resume/', views.ResumeScan.as_view()),
	url(r'^resume_conc/', views.ResumeScanConc.as_view()),
	url(r'^resume_scanning/', views.ResumeExploits.as_view()),
	url(r'^projects/', views.ExploitableProjects.as_view()),
	url(r'^config/', views.ExploitConfig.as_view()),
	url(r'^config_conc/', views.ExploitConfigConc.as_view()),
	url(r'^config_overwrite/', views.ExploitConfig_overwrite.as_view()),
	url(r'^launch_scanning/', views.LaunchExploits.as_view()),
	url(r'^launch_scanning_concurrent/',views.LaunchExploitsConcurrent.as_view()),
	url(r'^upload/', views.UploadNmapXml.as_view()),
	url(r'^uploadNessus/', views.UploadNessusXml.as_view()),
	url(r'^uploadQualys/', views.UploadQualysXml.as_view()),
	url(r'^mergeReports/', views.MergeReports.as_view()),
	url(r'^reportOnFly/', views.ReportOnFly.as_view()),
	url(r'^downloadAll/', views.DownloadAllMannual.as_view()),
	#url(r'^nessusOnFly/', views.NessusOnFly.as_view()),

	
]

"""
"""from django.conf.urls import url
from django.contrib import admin
#from Dictator_service
import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
	url(r'^users/', views.UserList.as_view()),
	url(r'^csrf/', views.SetCsrf.as_view()),
	url(r'^scan/', views.StartScan.as_view()),
	url(r'^scan_concurrent/', views.StartScanConcurrent.as_view()),
	url(r'^polling/', views.PollingConfig.as_view()),
	url(r'^percentPolling/', views.PercentPolling.as_view()),
	url(r'^polling_scanning/', views.PollingExploit.as_view()),
	url(r'^stop/', views.StopScan.as_view()),
	url(r'^stop_conc/', views.StopScanConc.as_view()),
	url(r'^stop_scanning/', views.StopExploits.as_view()),
	url(r'^resume/', views.ResumeScan.as_view()),
	url(r'^resume_conc/', views.ResumeScanConc.as_view()),
	url(r'^resume_scanning/', views.ResumeExploits.as_view()),
	url(r'^projects/', views.ExploitableProjects.as_view()),
	url(r'^config/', views.ExploitConfig.as_view()),
	url(r'^config_conc/', views.ExploitConfigConc.as_view()),
	url(r'^config_overwrite/', views.ExploitConfig_overwrite.as_view()),
	url(r'^launch_scanning/', views.LaunchExploits.as_view()),
	url(r'^launch_scanning_concurrent/',views.LaunchExploitsConcurrent.as_view()),
	url(r'^upload/', views.UploadNmapXml.as_view()),
	url(r'^uploadNessus/', views.UploadNessusXml.as_view()),
	url(r'^uploadQualys/', views.UploadQualysXml.as_view()),
	url(r'^mergeReports/', views.MergeReports.as_view()),
	url(r'^reportOnFly/', views.ReportOnFly.as_view()),
	url(r'^downloadAll/', views.DownloadAllMannual.as_view()),
	#url(r'^nessusOnFly/', views.NessusOnFly.as_view()),

	
]
"""


