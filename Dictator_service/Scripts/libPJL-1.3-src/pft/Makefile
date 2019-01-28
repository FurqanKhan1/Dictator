CPP=g++
CPPFLAGS= -Wall -g -DUNIX -L../ -I../
DEBUGGING= -D_DEBUG
AR=ar rcs 
RM=rm -f 

SOURCES=main.cpp
HEADERS=
OBJECTS=main.o


pft: $(OBJECTS)
	$(CPP) $(CPPFLAGS) $(DEBUGGING) -o pft main.o -lPJL

%.o: %.cc %.h $(HEADERS)
	$(COMPILE.cpp) $(DEBUGGING) $< $(OUTPUT_OPTION)

clean:
	$(RM) $(OBJECTS) pft
