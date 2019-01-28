/* FX string class
 *
 * $Id: fxstrings.cpp,v 1.4 2005/04/21 07:37:28 fx Exp fx $
 */

#include <iostream>
using namespace std;
#include <string.h>
#include <stdlib.h>

#include "fxstrings.h"

/* Initializes the protected variables */
String::String(void) {
    str=NULL;
    ret_val=NULL;
    l=0;
}


String::String(char *s) {

	if (s==NULL) {
		str=NULL;
		ret_val=NULL;
		l=0;
		return;
	}

    str=(char*)malloc(strlen(s)+1);
    if (str==NULL) {
		throw ExMalloc();
    }
    memset(str,0,strlen(s)+1);
    strcpy(str,s);
    l=strlen(s);
    ret_val=NULL;
}


String::~String(void) {
    l=0;
    if (str!=NULL) free(str);
    str=NULL;
    if (ret_val!=NULL) free(ret_val);
    ret_val=NULL;
}


void String::set(char *s) {

	if (s==NULL) {
		clear();
		return;
	}

	if (str!=NULL) free(str);

    if ((str=(char*)malloc(strlen(s)+1))==NULL) {
#ifdef _DEBUG
		cerr << "String::set(): malloc failed\n";
#endif //_DEBUG
		throw ExMalloc();
    }
    memset(str,0,strlen(s)+1);
    strcpy(str,s);
    l=strlen(s);
    ret_val=NULL;
}


void String::set(void *s, unsigned int length) {
	char		*p;

	if (s==NULL) {
		clear();
		return;
	}

	if ((p=(char *)malloc(length+1))==NULL) {
#ifdef _DEBUG
		cerr << "String::set(char,len): malloc failed\n" << endl;
#endif //_DEBUG
		throw ExMalloc();
	}

	// copy data into temporary pointer
	memcpy(p,s,length);
	// terminate with zero
	p[length]='\0';

	clear();

    if ((str=(char*)malloc(strlen(p)+1))==NULL) {
#ifdef _DEBUG
		cerr << "String::set(char,len): malloc failed\n";
#endif //_DEBUG
		throw ExMalloc();
    }
    memset(str,0,strlen(p)+1);
    strcpy(str,p);
    l=strlen(p);
    ret_val=NULL;
	free(p);
}


void String::append(char *s) {

	if (str==NULL) {
		set(s);
		return;
	}
    str=(char*)realloc(str,l+strlen(s)+1);
    if (str==NULL) {
		throw ExMalloc();
    }
    strcat(str,s);
    l=l+strlen(s);
}


void String::clear(void) {

    if (str!=NULL) free(str);
    str=NULL;
    l=0;
}


char *String::get(void) {
    return (str);
}


unsigned int String::length(void) {
    return (l);
}


/* fxstrntok() - from the CyN projects ;)
 *
 * DESCRITION
 * 	The function returns the n-th token of string *s seperated 
 * 	by delim. The counting starts by 0.
 *
 * RETURNS
 * 	pointer to new allocated memory area in ret_val 
 * 	containing token or NULL if not found.
 * 	ret_val is erased and recreated for subsequent calls, so you should not
 * 	use an once obtained pointer after you called token() again
 */

char *String::token(char delim, unsigned int n) {
    unsigned int	n1=0;
    char		*ptr_a,*ptr_b;

    /* free old token */
    if (ret_val!=NULL) free(ret_val);
    ret_val=NULL;

    /* return NULL if the initial string *str is NULL */
    if (str==NULL) return NULL;

    /* if delim is not found at least one time, return NULL */
    if ((ptr_a=strchr(str,delim))==NULL) return NULL;

    /* if the first (index 0) token is requested, return the token 
     * right now */
    if (n==0) {
		/* allocate memory of the size pointer_to_delim minus pointer
		 * to string. This is pointer arithmetic and returns the number
		 * of elements (chars) between the two memory locations. It 
		 * uses the of _types_ of the pointer - so be carefull */
		if ((ret_val=(char *)malloc((ptr_a-str)+1))==NULL)
			return NULL;
		/* copy the string to the return pointer */
		memset(ret_val,0,(ptr_a-str)+1);
		strncpy(ret_val,str,ptr_a-str);
		return ret_val;
    } else {
		/* not the first is requested, so go on */
		n1++;
		/* if the char right after the last occurance of delim is \0, 
		 * the string ends here. Return NULL */
		if ((++ptr_a)[0]=='\0') return NULL;
		/* while there is a chunk of memory between this and the next
		 * delim ... */
		while ((ptr_b=strchr(ptr_a,delim))!=NULL) {
			/* if this is the requested chunk ... */
			if (n1==n) {
			/* if the chunk is 0 sized, return an empty string */
				if ((ptr_b-ptr_a)==0) {
					if ((ret_val=(char *)malloc(1))==NULL) return NULL;
					memset(ret_val,0,1);
					return ret_val;
				} else {
					/* otherwise return the chunk */
					if ((ret_val=(char *)malloc((ptr_b-ptr_a)+1))==NULL)
						return NULL;
					memset(ret_val,0,(ptr_b-ptr_a)+1);
					strncpy(ret_val,ptr_a,ptr_b-ptr_a);
					return ret_val;
				}
			}
			/* increment the number of chunks we've seen */
			n1++;
			/* next point to start from is one after the delim */
			ptr_a=++ptr_b;
		}
		/* so we did not find <delim>string<delim>. May be this is the 
		 * case <delim>string<end> ... */
		if (n1==n) {
			if (strlen(ptr_a)==0) {
				if ((ret_val=(char *)malloc(1))==NULL) return NULL;
				memset(ret_val,0,1);
				return ret_val;
			}
			if ((ret_val=(char *)malloc(strlen(ptr_a)+1))==NULL)
				return NULL;
			memset(ret_val,0,strlen(ptr_a)+1);
			strncpy(ret_val,ptr_a,strlen(ptr_a));
			return ret_val;
		}
	/* not found anything... return NULL */
	return NULL;
    }
}


/* stoken() - from the CyN projects and then modified again ;)
 *
 * DESCRITION
 * 	The function returns the n-th token of string *s seperated 
 * 	by delim. The counting starts by 0. Delim is a string instead of a character.
 *
 * RETURNS
 * 	pointer to new allocated memory area in ret_val 
 * 	containing token or NULL if not found.
 * 	ret_val is erased and recreated for subsequent calls, so you should not
 * 	use an once obtained pointer after you called stoken() again
 */

char *String::stoken(char *delim, unsigned int n) {
    unsigned int	n1=0;
    char			*ptr_a,*ptr_b;

    /* free old token */
    if (ret_val!=NULL) free(ret_val);
    ret_val=NULL;

    /* return NULL if the initial string *s is NULL */
    if (str==NULL) return NULL;

	/* return NULL is the delim string is NULL */
	if (delim==NULL) return NULL;

	/* also return NULL if the delim is longer then str since we cannot 
	 * be sure that strstr() can cope with that */
	if (strlen(delim)>l) return NULL;

    /* if delim is not found at least one time, return NULL */
    if ((ptr_a=strstr(str,delim))==NULL) return NULL;

    /* if the first (index 0) token is requested, return the token 
     * right now */
    if (n==0) {
		/* allocate memory of the size pointer_to_delim minus pointer
		 * to string. This is pointer arithmetic and returns the number
		 * of elements (chars) between the two memory locations. It 
		 * uses the of _types_ of the pointer - so be carefull */
		if ((ret_val=(char *)malloc((ptr_a-str)+1))==NULL)
			return NULL;
		/* copy the string to the return pointer */
		memset(ret_val,0,(ptr_a-str)+1);
		strncpy(ret_val,str,ptr_a-str);
		return ret_val;
    } else {
		/* not the first is requested, so go on */
		n1++;
		/* if the char right after the last occurance of delim is \0, 
		 * the string ends here. Return NULL */
		ptr_a=ptr_a+strlen(delim);
		if (ptr_a[0]=='\0') return NULL;
		/* while there is a chunk of memory between this and the next
		 * delim ... */
		while ((ptr_b=strstr(ptr_a,delim))!=NULL) {
			/* if this is the requested chunk ... */
			if (n1==n) {
			/* if the chunk is 0 sized, return an empty string */
				if ((ptr_b-ptr_a)==0) {
					if ((ret_val=(char *)malloc(1))==NULL) return NULL;
					memset(ret_val,0,1);
					return ret_val;
				} else {
					/* otherwise return the chunk */
					if ((ret_val=(char *)malloc((ptr_b-ptr_a)+1))==NULL)
						return NULL;
					memset(ret_val,0,(ptr_b-ptr_a)+1);
					strncpy(ret_val,ptr_a,ptr_b-ptr_a);
					return ret_val;
				}
			}
			/* increment the number of chunks we've seen */
			n1++;
			/* next point to start from is one after the delim */
			ptr_a=ptr_b+strlen(delim);
		}
		/* so we did not find <delim>string<delim>. May be this is the 
		 * case <delim>string<end> ... */
		if (n1==n) {
			if (strlen(ptr_a)==0) {
				if ((ret_val=(char *)malloc(1))==NULL) return NULL;
				memset(ret_val,0,1);
				return ret_val;
			}
			if ((ret_val=(char *)malloc(strlen(ptr_a)+1))==NULL)
				return NULL;
			memset(ret_val,0,strlen(ptr_a)+1);
			strncpy(ret_val,ptr_a,strlen(ptr_a));
			return ret_val;
		}
	/* not found anything... return NULL */
	return NULL;
    }
}


bool String::operator == (String s) {

	if (this == &s) return true;
	if (str==NULL) return false;

	if (strcmp(str,s.get())==0) {
		return true;
	} else {
		return false;
	}
}


bool String::operator == (char *other) {

	if ((str==NULL)||(other==NULL)) return false;

	if (strcmp(str,other)==0) {
		return true;
	} else {
		return false;
	}
}


void String::operator = (char *s) {
	set(s);
}


void String::chomp(void) {
	if ((l>0)&&(str[l-1]=='\n')) {
		str[--l]='\0';
	}

	if ((l>0)&&(str[l-1]=='\r')) {
		str[--l]='\0';
	}
}


char *String::findstr(char *needle) {

	if ((str==NULL)||(needle==NULL)) return NULL;

	return (strstr(str,needle));
}

void String::multispace2tab(void) {
	char		*b;
	unsigned int	i=0,j=0;
	bool		curspace=false;

	if (l<1) return;

	if ((b=(char*)malloc(l+1))==NULL) throw ExMalloc();
	memset(b,0,l+1);

	while (i<l) {
		if (str[i]!=' ') {
			b[j++]=str[i++];
			curspace=false;
		} else {
			if (!curspace) {
				b[j++]='\t';
				i++;
				curspace=true;
			} else {
				i++;
			}
		}
	}

	free(str);
	if ((str=(char*)malloc(strlen(b)+1))==NULL) throw ExMalloc();
	memset(str,0,strlen(b)+1);
	strcpy(str,b);
	l=strlen(b);
	free(b);
}
