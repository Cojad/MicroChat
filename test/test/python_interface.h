#pragma once
#include "python_interface_base.h"

#define MODULE_NAME_INTERFACE		"interface"
#define MODULE_NAME_MAIN			"main"
#define FUNCTION_INITALL			"InitAll"
#define FUNCTION_GETDNS				"GetDns"
#define FUNCTION_LOGIN				"Login"
#define FUNCTION_NEWINIT			"new_init"
#define FUNCTION_START				"start"

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
	void Start(CStringA strUserName, CStringA strPassword);
private:
	
};
#define pPython (CPython::GetInstance())

