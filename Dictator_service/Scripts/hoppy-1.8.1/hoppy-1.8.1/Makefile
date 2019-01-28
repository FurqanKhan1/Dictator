VERSION = 1.8.1 
PREFIX_DIR = $(PREFIX)
ETC = /etc/hoppy
SHARE = $(PREFIX_DIR)/usr/local/share/hoppy
LIB_DIR = $(SHARE)/lib
INSTALL_DIR = $(PREFIX_DIR)/usr/local/bin
install:
	cat message
	install -d $(ETC)
	install -d $(SHARE)
	install -d $(INSTALL_DIR)
	install -d $(SHARE)/lib
	install -d $(SHARE)/example-methods
	if [ -e $(INSTALL_DIR)/hoppy ]; then rm $(INSTALL_DIR)/hoppy; fi;
	ln -s $(SHARE)/hoppy $(INSTALL_DIR)/hoppy
	install lib/hopclass.py $(LIB_DIR)
	cp example-methods/* $(SHARE)/example-methods
	install hoppy response-keywords http-methods $(SHARE)
	if ! [ -e $(ETC)/hoppy.conf ]; then install hoppy.conf $(ETC); fi;
