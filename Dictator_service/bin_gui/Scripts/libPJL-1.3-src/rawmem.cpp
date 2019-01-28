/* Rawmem class
 *
 * $Id: rawmem.cpp,v 1.3 2005/04/21 07:37:28 fx Exp fx $
 */
#include <iostream>
using namespace std;
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef UNIX
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif //UNIX

#include "rawmem.h"

Rawmem::Rawmem() {
	mem=NULL;
	len=0;
	ch=NULL;
}


Rawmem::Rawmem(void *src, unsigned int size) {
	mem=NULL;
	len=0;
	ch=NULL;

	if ((mem=malloc(size))==NULL) {
		throw ExMalloc();
	}
	memset(mem,0,size);

	memcpy(mem,src,size);
	len=size;
}


Rawmem::~Rawmem() {
	if (mem!=NULL) free(mem);
	if (ch!=NULL) free(ch);
	len=0;
}


void Rawmem::set(void *src, unsigned int size) {
	if (mem!=NULL) free(mem);
	if ((mem=malloc(size))==NULL) {
		throw ExMalloc();
	}
	memset(mem,0,size);

	memcpy(mem,src,size);
	len=size;
}


void Rawmem::set(char *src) {
	set((void *)src,strlen(src));
}

	
void Rawmem::append(void *src, unsigned int size) {
	void	*p;

	if ((p=realloc(mem,len+size))==NULL) {
		throw ExMalloc();
	}
	mem=p;
	p=(void *)((char *)p+len);
	memset(p,0,size);
	memcpy(p,src,size);
	len+=size;
}


void Rawmem::append(char *src) {
	append((void *)src,strlen(src));
}


void *Rawmem::chunk(unsigned int start, unsigned int *size) {
	void	*p;
	
	if (ch!=NULL) free(ch);
	if (start>=len) return NULL;
	if ((start-len)<(*size)) *size=start-len;

	if ((ch=malloc(*size))==NULL) {
		throw ExMalloc();
	}
	memset(ch,0,*size);

	p=(void *)((char *)mem+start);
	memcpy(ch,p,*size);

	return ch;
}


unsigned int Rawmem::length() {
	return (len);
}


void *Rawmem::get() {
	return mem;
}


void Rawmem::clear() {
	if (mem!=NULL) { 
		free(mem);
		mem=NULL;
	}
	if (ch!=NULL) {
		free(ch);
		ch=NULL;
	}
	len=0;
}


/* A better version of hdump, from Lamont Granquist.  
   Modified slightly by Fyodor (fyodor@DHP.com) 
   obviously stolen from nmap (util.c)*/
void Rawmem::dump(void) {
  static const char asciify[] = 
	  "................................ "
	  "!\"#$%&'()*+,-./0123456789:;<=>?@"
	  "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
	  "abcdefghijklmnopqrstuvwxyz{|}~..."
	  "................................."
	  "................................."
	  "................................."
	  "..........................."; 

  unsigned char			*bp = (unsigned char *)mem;
  unsigned int			length = len;

  const unsigned short *sp;
  const unsigned char *ap;
  unsigned int i, j;
  int nshorts, nshorts2;
  int padding;

  printf("\n\t");
  padding = 0;
  sp = (unsigned short *)bp;
  ap = (unsigned char *)bp;
  nshorts = (unsigned int) length / sizeof(unsigned short);
  nshorts2 = (unsigned int) length / sizeof(unsigned short);
  i = 0;
  j = 0;
  while(1) {
    while (--nshorts >= 0) {
      printf(" %04x", ntohs(*sp));
      sp++;
      if ((++i % 8) == 0)
        break;
    }
    if (nshorts < 0) {
      if ((length & 1) && (((i-1) % 8) != 0)) {
        printf(" %02x  ", *(unsigned char *)sp);
        padding++;
      }
      nshorts = (8 - (nshorts2 - nshorts));
      while(--nshorts >= 0) {
        printf("     ");
      }
      if (!padding) printf("     ");
    }
    printf("  ");

    while (--nshorts2 >= 0) {
      printf("%c%c", asciify[*ap], asciify[*(ap+1)]);
      ap += 2;
      if ((++j % 8) == 0) {
        printf("\n\t");
        break;
      }
    }
    if (nshorts2 < 0) {
      if ((length & 1) && (((j-1) % 8) != 0)) {
        printf("%c", asciify[*ap]);
      }
      break;
    }
  }
  if ((length & 1) && (((i-1) % 8) == 0)) {
    printf(" %02x", *(unsigned char *)sp);
    printf("                                       %c", asciify[*ap]);
  }
  printf("\n");
}


bool Rawmem::findchr(char c) {
	unsigned int	i;
	char			*p;
	bool			found=false;

	if (mem==NULL) return false;
	p=(char *)mem;
	for (i=0;i<len;i++) {
		if ((found=(p[i]==c))) break;
	}

	return found;
}


bool Rawmem::findstr(char *str) {
	unsigned int	i;
	char			*p;
	bool			found=false;

	if (mem==NULL) return false;
	if (strlen(str)>len) return false;

	p=(char *)mem;
	for (i=0;i<=(len-strlen(str));i++) {
		if (memcmp(p,str,strlen(str))==0) {
			found=true;
			break;
		} 
		p++;
	}

	return found;
}
