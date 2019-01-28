/* PJL lists based on llist.cpp 
 * 
 * $Id: pjllists.cpp,v 1.4 2005/04/21 07:37:28 fx Exp fx $
 */
#include <iostream>
using namespace std;

#include "pjllists.h"

/* **************************
 * PJLenv 
 * **************************/

void PJLenv::add_front(PJLenvPrim *e) {
	LinkList::add_front((ListPrimitive *)e);
}

void PJLenv::add_end(PJLenvPrim *e) {
	LinkList::add_end((ListPrimitive *)e);
}

PJLenvPrim *PJLenv::get_current(void) {
	return (PJLenvPrim *)LinkList::get_current();
}

PJLenvPrim *PJLenv::element(unsigned int num) {
	return (PJLenvPrim *)LinkList::element(num);
}

PJLenvPrim *PJLenv::element(char *vname) {
	unsigned int	i;
	PJLenvPrim		*e;
	String		t;

	for (i=0;i<LinkList::count();i++) {
		e=(PJLenvPrim *)LinkList::element(i);

		t=e->get_var()->get();
		if ( t==vname ) {
		//if ( (*(e->get_var())) ==vname ) {
			return e;
		}
	}
	return NULL;
}

String *PJLenv::operator[] (char *var) {
	unsigned int	i;
	PJLenvPrim		*e;
	String		t;

	for (i=0;i<LinkList::count();i++) {
		e=(PJLenvPrim *)LinkList::element(i);
		t=e->get_var()->get();
		if ( t==var ) {
			return e->get_val();
		}
	}
	return NULL;
}


/* **************************
 * PJLenvPrim 
 * **************************/

PJLenvPrim::~PJLenvPrim(void) {
}


void PJLenvPrim::print(void) {
	cout << variable.get() << "\t" << value.get() << 
		"\t(" << options.count() << " options)" << endl;
	options.dump();
}


void PJLenvPrim::set_lang(char *str) {
	lang.set(str);
}

void PJLenvPrim::set_var(char *str) {
	variable.set(str);
}


void PJLenvPrim::set_val(char *str) {
	value.set(str);
	set_changed(true);
}


String *PJLenvPrim::get_var(void) {
	return &variable;
}


String *PJLenvPrim::get_val(void) {
	return &value;
}


String *PJLenvPrim::get_lang(void) {
	return &lang;
}


unsigned int PJLenvPrim::options_count(void) {
	return options.count();
}


char *PJLenvPrim::option(unsigned int num) {
	StringElement	*se;

	se=(StringElement *)options.element(num);
	return se->get();
}


void PJLenvPrim::option_add(char *str) {
	StringElement	*se;

	se = new StringElement;
	se->set(str);
	options.add_end(se);
}

void PJLenvPrim::set_changed(bool yesno) {
	changed=yesno;
}

bool PJLenvPrim::get_changed(void) {
	return changed;
}

void PJLenvPrim::set_range(bool yesno) {
	range=yesno;
}

bool PJLenvPrim::get_range(void) {
	return range;
}
/* **************************
 * PJLvolPrim 
 * **************************/

PJLvolPrim::~PJLvolPrim(void) {
}

void PJLvolPrim::print(void) {
	cout << volume.get() 
		<< "\t" << size.get() 
		<< "\t" << free.get()
		<< "\t" << location.get()
		<< "\t" << label.get()
		<< "\t" << status.get()
		<< endl;
}

String *PJLvolPrim::get_volume(void) {
	return &volume;
}

String *PJLvolPrim::get_size(void) {
	return &size;
}

String *PJLvolPrim::get_free(void) {
	return &free;
}

String *PJLvolPrim::get_location(void) {
	return &location;
}

String *PJLvolPrim::get_label(void) {
	return &label;
}

String *PJLvolPrim::get_status(void) {
	return &status;
}

void PJLvolPrim::set_volume(char *str){
	volume.set(str);
}

void PJLvolPrim::set_size(char *str){
	size.set(str);
}

void PJLvolPrim::set_free(char *str){
	free.set(str);
}

void PJLvolPrim::set_location(char *str){
	location.set(str);
}

void PJLvolPrim::set_label(char *str){
	label.set(str);
}

void PJLvolPrim::set_status(char *str){
	status.set(str);
}

/* **************************
 * PJLvol
 * **************************/

void PJLvol::add_front(PJLvolPrim *e) {
	LinkList::add_front((ListPrimitive *)e);
}

void PJLvol::add_end(PJLvolPrim *e) {
	LinkList::add_end((ListPrimitive *)e);
}

PJLvolPrim *PJLvol::element(unsigned int num) {
	return (PJLvolPrim *)LinkList::element(num);
}

PJLvolPrim *PJLvol::element(char *vname) {
	unsigned int	i;
	PJLvolPrim		*e;

	for (i=0;i<LinkList::count();i++) {
		e=(PJLvolPrim *)LinkList::element(i);
		if ( (*(e->get_volume())) ==vname ) {
			return e;
		}
	}
	return NULL;
}


/* **************************
 * PJLfilePrim 
 * **************************/

PJLfilePrim::PJLfilePrim(void) {
	size=0;
	type=0;
}

PJLfilePrim::~PJLfilePrim(void) {
}

void PJLfilePrim::print(void) {
	cout << name.get() 
		<< "\t" << size  
		<< "bytes, type = " << type << endl;
}

void PJLfilePrim::set_name(char *str) {
	name.set(str);
}

void PJLfilePrim::set_size(unsigned int s) {
	size=s;
}

void PJLfilePrim::set_type(int t) {
	type=t;
}

String *PJLfilePrim::get_name(void) {
	return &name;
}

unsigned int PJLfilePrim::get_size(void) {
	return size;
}

int PJLfilePrim::get_type(void) {
	return type;
}

/* **************************
 * PJLfile
 * **************************/

void PJLfile::add_front(PJLfilePrim *e) {
	LinkList::add_front((ListPrimitive *)e);
}

void PJLfile::add_end(PJLfilePrim *e) {
	LinkList::add_end((ListPrimitive *)e);
}

PJLfilePrim *PJLfile::element(unsigned int num) {
	return (PJLfilePrim *)LinkList::element(num);
}

PJLfilePrim *PJLfile::element(char *vname) {
	unsigned int	i;
	PJLfilePrim		*e;

	for (i=0;i<LinkList::count();i++) {
		e=(PJLfilePrim *)LinkList::element(i);
		if ( (*(e->get_name())) ==vname ) {
			return e;
		}
	}
	return NULL;
}
