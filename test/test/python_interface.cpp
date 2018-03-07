#include "stdafx.h"
#include "python_interface.h"

CPython::CPython()
{
	ImportModule(MODULE_NAME_INTERFACE);
	RegisterPythonFunction(MODULE_NAME_INTERFACE, FUNCTION_INITALL);
	RegisterPythonFunction(MODULE_NAME_INTERFACE, FUNCTION_GETDNS);
	RegisterPythonFunction(MODULE_NAME_INTERFACE, FUNCTION_LOGIN);
}

CPython::~CPython()
{

}

CPython * CPython::GetInstance()
{
	static CPython *pInstance = new CPython;
	return pInstance;
}

void CPython::InitAll()
{
	PyObject*pRet = CallObject(MODULE_NAME_INTERFACE, FUNCTION_INITALL,NULL);
	
	PY_FREE(pRet);
}

BOOL CPython::GetDns(CStringA &strLonglinkIp, CStringA &strShortlinkIp)
{
	strLonglinkIp.Empty();
	strShortlinkIp.Empty();
	
	PyObject*pRet = CallObject(MODULE_NAME_INTERFACE, FUNCTION_GETDNS, NULL);

	if (pRet)
	{
		char *szLongIp	= NULL;
		char *szShortIp = NULL;

		PyObject* pLongIp = ParseResult(pRet, "longip", "s", (void **)&szLongIp);
		PyObject* pShortIp = ParseResult(pRet, "shortip", "s", (void **)&szShortIp);

		strLonglinkIp	= szLongIp;
		strShortlinkIp	= szShortIp;

		PY_FREE(pRet);
	}

	return !strLonglinkIp.IsEmpty() && !strShortlinkIp.IsEmpty();
}

int CPython::Login(CStringA strUserName, CStringA strPassword)
{
	int nCode = -1;
	
	PyObject *pRet = CallObject(MODULE_NAME_INTERFACE, FUNCTION_LOGIN, "(s,s)", strUserName, strPassword);

	if (pRet)
	{
		PyArg_Parse(pRet, "i", &nCode);

		PY_FREE(pRet);
	}	

	return nCode;
}
