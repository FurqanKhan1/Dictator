/* 
 * linked list first attempt of implementation
 *
 * $Id: llist.cpp,v 1.3 2005/04/21 07:37:28 fx Exp fx $
 */

#include <iostream>
using namespace std;
#include <string.h>
#include <stdlib.h>

#include "llist.h"

LinkList::LinkList() {
	anchor=current=NULL;
}


LinkList::~LinkList() {
	while (anchor!=NULL) {
		current=anchor;
		anchor=anchor->get_next();
		delete current;
	}
	anchor=current=NULL;
}


void LinkList::clear(void) {
	while (anchor!=NULL) {
		current=anchor;
		anchor=anchor->get_next();
		delete current;
	}
	anchor=current=NULL;
}


void LinkList::add_front(ListPrimitive *prim) {
	ListPrimitive	*l;

	l=anchor;
	anchor=prim;
	prim->set_next(l);
	current=anchor;
}


void LinkList::add_end(ListPrimitive *prim) {
	ListPrimitive	*l;

	if (anchor==NULL) {
		add_front(prim);
	} else {
		l=anchor;
		while (l->get_next()!=NULL) l=l->get_next();
		l->set_next(prim);
		prim->set_next(NULL);
		current=prim;
	}
}


void LinkList::dump(void) {

	current=anchor;
	while (current!=NULL) {
		current->print();
		current=current->get_next();
	}
	current=anchor;
}


ListPrimitive *LinkList::get_current(void) {
	return current;
}


unsigned int LinkList::count(void) {
	unsigned int	i=0;
	ListPrimitive	*l;

	l=anchor;
	while (l!=NULL) {
		l=l->get_next();
		i++;
	}

	return i;
}


ListPrimitive *LinkList::element(unsigned int num) {
	unsigned int	i=0;
	ListPrimitive	*l;

	l=anchor;
	while (l!=NULL) {
		if (i==num) {
			current=l;
			break;
		}
		i++;
		l=l->get_next();
	}

	if (l==NULL) {
		throw ExInvalid();
	} 
	return l;
}



/* ***************************
 * ListPrimitive 
 * ***************************/

ListPrimitive::ListPrimitive(void) {
	next=NULL;
}


ListPrimitive::~ListPrimitive(void) {
	next=NULL;
}


void ListPrimitive::set_next(ListPrimitive *attach) {
	next=attach;
}


ListPrimitive *ListPrimitive::get_next(void) {
	return next;
}


void ListPrimitive::print(void) {
//	cout << "\n" << endl;
}


/* ***************************
 * String Element
 * ***************************/

StringElement::~StringElement(void) {
}


void StringElement::print(void) {
	cout << s.get() << endl;
}


void StringElement::set(char *str) {
	s.set(str);
}


char *StringElement::get(void) {
	return s.get();
}

