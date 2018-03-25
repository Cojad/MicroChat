#pragma once
#include "python_interface_base.h"

#define MODULE_NAME_INTERFACE		"interface"
#define FUNCTION_INITALL			"InitAll"
#define FUNCTION_GETDNS				"GetDns"
#define FUNCTION_LOGIN				"Login"
#define FUNCTION_NEWINIT			"new_init"

class CPython : public CPythonBase
{
public:
	CPython();
	~CPython();

	static CPython *GetInstance();

	void InitAll();
	BOOL GetDns(CStringA &strLonglinkIp, CStringA &strShortlinkIp);
	int Login(CStringA strUserName, CStringA strPassword);
	void NewInit();
private:
	
};
#define pPython (CPython::GetInstance())

