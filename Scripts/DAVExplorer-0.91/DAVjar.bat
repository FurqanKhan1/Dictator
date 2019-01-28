@echo off
cd classes
c:\jdk1.2.2\bin\jar -cfm DAVExplorer.jar DAVManifest edu\uci\ics\DAVExplorer\*.class edu\uci\ics\DAVExplorer\icons\* HTTPClient\*.class HTTPClient\http\*.class HTTPClient\https\*.class HTTPClient\shttp\*.class com\ms\xml\dso\*.class com\ms\xml\om\*.class com\ms\xml\parser\*.class com\ms\xml\util\*.class com\ms\xml\xmlstream\*.class
move DAVExplorer.jar ..
cd ..
