/* base class for exceptions 
 * $Id: exceptions.h,v 1.3 2005/04/21 07:37:28 fx Exp fx $ 
 */

#ifndef __EXCPETIONS_H__
#define __EXCPETIONS_H__

class BaseExceptions {
	public:
		// This exception is thrown for failed malloc() operations
		class ExMalloc{};

		// ExInvalid() is thrown for functions called with 
		// correct types of arguments that make no sense in
		// the current context
		class ExInvalid{};
};

#endif //__EXCPETIONS_H__
