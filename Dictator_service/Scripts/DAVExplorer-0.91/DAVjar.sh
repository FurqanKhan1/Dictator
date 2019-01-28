#!/bin/sh
cd classes; jar -cfm DAVExplorer.jar DAVManifest edu/uci/ics/DAVExplorer/*.class edu/uci/ics/DAVExplorer/icons/* HTTPClient/*.class HTTPClient/http/*.class HTTPClient/https/*.class HTTPClient/shttp/*.class com/ms/xml/dso/*.class com/ms/xml/om/*.class com/ms/xml/parser/*.class com/ms/xml/util/*.class com/ms/xml/xmlstream/*.class; mv DAVExplorer.jar ..

