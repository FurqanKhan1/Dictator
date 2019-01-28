/* TCPcon class implementation
 *
 * $Id: tcpcon.cpp,v 1.3 2005/04/21 07:37:28 fx Exp fx $
 */
#include <iostream>
using namespace std;

#include <string.h>
#include <time.h>

#ifndef UNIX
#include <winsock2.h>
#else
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
// defined on Windows but not on UNIX 
#define INVALID_SOCKET		(-1)
#define SOCKET_ERROR		(-1)
#endif //UNIX

#include "tcpcon.h"

TCPcon::TCPcon() {
#ifndef UNIX
	WORD wVersionRequested; 
	WSADATA wsaData; 
#endif //UNIX
	
	// initialize values
	memset(&dest,0,sizeof(dest));
	timeout.tv_sec = DEF_TIMEOUT_SEC;
	timeout.tv_usec = DEF_TIMEOUT_USEC;
	sfd=0;
	connected=false;
	
#ifndef UNIX
	// kick off WinSock
	wVersionRequested = MAKEWORD(1, 1); 
	if (WSAStartup(wVersionRequested, &wsaData)!=0) {
#ifdef _DEBUG
		cerr << "TCPcon::TCPcon() starting WSA failed\n";
#endif //_DEBUG
		throw ExWinSock();
	}
#endif //UNIX
}


TCPcon::~TCPcon() {
	if (connected) closeconnection();
#ifndef UNIX
	WSACleanup();
#endif //UNIX
}


void TCPcon::set_host(char *host) {
	struct hostent	*he;

	if ((he=gethostbyname(host))==NULL) {
#ifdef _DEBUG
		cerr << "TCPcon::set_host(): gethostbyname() failed\n";
#endif //_DEBUG
		throw ExResolver();
	}

	memcpy(&(dest.sin_addr), he->h_addr, he->h_length); 
    dest.sin_family = he->h_addrtype;
}


void TCPcon::set_port(unsigned int port) {
	
	if ((port<=0)||(port>65535)) {
#ifdef _DEBUG
		cerr << "TCPcon::set_port(): port out of range\n";
#endif //_DEBUG
		throw ExInvalid();
	}
	dest.sin_port=htons(port);
}


void TCPcon::startconnection(void) {

	if (connected) {
		throw ExInvalid();
	}

	// check if IP address and port are set
	if ( ntohs(*((unsigned short *)(&(dest.sin_port))))==0 ) {
#ifdef _DEBUG
		cerr << "TCPcon::startconnection(): port not set\n";
#endif //_DEBUG
		throw ExInvalid();
	}

	if ((sfd=socket(AF_INET,SOCK_STREAM,0))==INVALID_SOCKET) {
#ifdef _DEBUG
		cerr << "TCPcon::startconnection(): socket() failed\n";
#endif //_DEBUG
		throw ExSocket();
	}

	if (connect(sfd,(struct sockaddr *)&dest,sizeof(dest))!=0) {
#ifdef _DEBUG
		cerr << "TCPcon::startconnection(): connect() failed\n";
#endif //_DEBUG
		throw ExSocket();
	}

	connected=true;
}


void TCPcon::closeconnection(void) {
	if (connected) {
#ifndef UNIX
		closesocket(sfd);
#else
		close(sfd);
#endif //UNIX
	}
	connected=false;
}


bool TCPcon::is_connected(void) {
	return connected;
}


void TCPcon::set_timeout(long sec, long usec) {
	timeout.tv_sec=sec;
	timeout.tv_usec=usec;
}


long TCPcon::get_timeout_sec(void) {
	return (timeout.tv_sec);
}


long TCPcon::get_timeout_usec(void) {
	return (timeout.tv_usec);
}


void TCPcon::senddata(void) {

	if (sendbuf.length()==0) {
#ifdef _DEBUG
		cerr << "TCPcon::send(): send buffer empty\n";
#endif //_DEBUG
		throw ExInvalid();
	}

	if (send(sfd,(char *)sendbuf.get(),sendbuf.length(),0)==SOCKET_ERROR) {
#ifdef _DEBUG
		cerr << "TCPcon::send(): send() failed\n";
#endif //_DEBUG
		throw ExSocket();
	}
}


void TCPcon::recvdata(void) {
	char			*tp;
	fd_set			rfds;
	int				num_recvd=0;

	if ((tp=(char *)malloc(TPSIZE))==NULL) {
#ifdef _DEBUG
		cerr << "TCPcon::recvdata(): malloc() failed\n";
#endif //_DEBUG
		throw ExMalloc();
	}
	
	memset(tp,0,TPSIZE);
	FD_ZERO(&rfds);
	FD_SET((u_int)sfd,&rfds);

	select(sfd+1,&rfds,NULL,NULL,&timeout);
	if (!FD_ISSET(sfd,&rfds)) {
//#ifdef _DEBUG
//		cerr << "TCPcon::recvdata(): select timed out\n";
//#endif //_DEBUG
		throw ExTimeout();
	}

	num_recvd=recv(sfd,tp,TPSIZE,0);
	if (num_recvd==SOCKET_ERROR)
		throw ExSocket();
	if (num_recvd>0)
		recvbuf.append((void *)tp,num_recvd);
}


void TCPcon::recvbyte(void) {
	char			tp[2];
	fd_set			rfds;
	int				num_recvd=0;
	
	memset(tp,0,2);
	FD_ZERO(&rfds);
	FD_SET((u_int)sfd,&rfds);

	select(sfd+1,&rfds,NULL,NULL,&timeout);
	if (!FD_ISSET(sfd,&rfds)) {
//#ifdef _DEBUG
//		cerr << "TCPcon::recvdata(): select timed out\n";
//#endif //_DEBUG
		throw ExTimeout();
	}

	num_recvd=recv(sfd,tp,1,0);
	if (num_recvd==SOCKET_ERROR)
		throw ExSocket();
	if (num_recvd>0)
		recvbuf.append((void *)tp,num_recvd);
}


void TCPcon::recvuntilchr(char c, unsigned long timer) {
	unsigned long	start_t;
	bool			found=false;

	start_t=(unsigned long)time(NULL);
	while (start_t+timer>(unsigned long)time(NULL)) {
		try {
			recvbyte();
		} catch (TCPcon::ExTimeout) {
			// do nothing
		}
		if ((found=recvbuf.findchr(c))) break;
	}

	if (!found) {
		throw ExTimeout();
#ifdef _DEBUG
		cerr << "TCPcon::recvuntilchr(): timed out\n";
#endif //_DEBUG
	}
}


void TCPcon::recvuntilstr(char *str, unsigned long timer) {
	unsigned long	start_t;
	bool			found=false;

	start_t=(unsigned long)time(NULL);
	while (start_t+timer>(unsigned long)time(NULL)) {
		try {
			recvbyte();
		} catch (TCPcon::ExTimeout) {
			// do nothing
		}
		if ((found=recvbuf.findstr(str))) break;
	}

	if (!found) {
		throw ExTimeout();
#ifdef _DEBUG
		cerr << "TCPcon::recvuntilstr(): timed out\n";
#endif //_DEBUG
	}
}


void TCPcon::recvatleast(unsigned int n, unsigned long timer) {
	unsigned long	start_t;
	bool			found=false;

	start_t=(unsigned long)time(NULL);
	while (start_t+timer>(unsigned long)time(NULL)) {
		try {
			recvbyte();
		} catch (TCPcon::ExTimeout) {
			// do nothing
		}
		if (found=(recvbuf.length()>=n)) break;
	}

	if (!found) {
		throw ExTimeout();
#ifdef _DEBUG
		cerr << "TCPcon::recvatleast(): timed out\n";
#endif //_DEBUG
	}
}


void *TCPcon::get(void) {
	return (recvbuf.get());
}


unsigned int TCPcon::length(void) {
	return (recvbuf.length());
}


void TCPcon::set(void *s, unsigned int size) {
	sendbuf.set(s,size);
}


void TCPcon::set(char *s) {
	sendbuf.set(s);
}


void TCPcon::clear(void) {
	sendbuf.clear();
	recvbuf.clear();
}
