#
# UNIX style makefile for libPJL 
#
#

CPPFLAGS= -Wall -g -DUNIX -D_DEBUG
AR=ar rcs 
RM=rm -f 

SOURCES=commands.h exceptions.h fxstrings.cpp fxstrings.h llist.cpp llist.h\
	pjllists.cpp pjllists.h pjlsession.cpp pjlsession.h rawmem.cpp rawmem.h\
	tcpcon.cpp tcpcon.h

HEADERS=commands.h exceptions.h fxstrings.h llist.h\
	pjllists.h pjlsession.h rawmem.h tcpcon.h

WINDOWSFILES=PJLlib.dsp PJLlib.dsw PJLlib.ncb PJLlib.opt PJLlib.plg
PFTFILES=pft/Makefile pft/main.cpp pft/pft.dsp pft/pft.plg

OBJECTS=fxstrings.o llist.o pjllists.o pjlsession.o rawmem.o tcpcon.o


libPJL.a: $(OBJECTS)
	$(AR) libPJL.a $(OBJECTS)

%.o: %.cc %.h $(HEADERS)
	$(COMPILE.cpp) $< $(OUTPUT_OPTION)

srctree:
	tar cvzf libPJL-source.tgz $(SOURCES) $(HEADERS) $(WINDOWSFILES) \
	Makefile $(PFTFILES) libPJL.version

clean:
	$(RM) $(OBJECTS) libPJL.a
