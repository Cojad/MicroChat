#include "stdafx.h"
#include "python_interface_base.h"


CPythonBase::CPythonBase()
{
	Init();
}

CPythonBase::~CPythonBase()
{
	Py_Finalize();
}

PyObject * CPythonBase::ImportModule(LPCSTR szModuleName)
{
	PyObject *pModule = PyImport_ImportModule(szModuleName);
	
	if (pModule)
	{
		CPyModule *pPyModule = new CPyModule;
		if (pPyModule)
		{
			pPyModule->m_pModule = pModule;
			m_map.insert(make_pair(szModuleName,pPyModule));
		}
	}
	else
	{
#ifdef USE_CONSOLE
		PyErr_Print();
#endif
		assert(pModule);
	}
	
	return pModule;
}

BOOL CPythonBase::RegisterPythonFunction(LPCSTR szModuleName, LPCSTR szFuncName)
{
	map<CStringA, CPyModule*>::iterator iter = m_map.find(szModuleName);
	if (m_map.end() != iter)
	{
		CPyModule *pPyModule = iter->second;
		
		if (pPyModule && pPyModule->m_pModule)
		{
			PyObject* pv = PyObject_GetAttrString(pPyModule->m_pModule, szFuncName);
			assert(pv);
			if (pv && PyCallable_Check(pv))
			{
				pPyModule->m_FuncMap.insert(make_pair(szFuncName, pv));
				return TRUE;
			}
		}
	}	
	
	return FALSE;
}

PyObject * CPythonBase::CallObject(LPCSTR szModuleName, LPCSTR szFuncName, LPCSTR szArgsFormat, ...)
{
	map<CStringA, CPyModule*>::iterator iter = m_map.find(szModuleName);
	if (m_map.end() != iter)
	{
		CPyModule *pPyModule = iter->second;

		if (pPyModule)
		{
			map<CStringA, PyObject*>::iterator it = pPyModule->m_FuncMap.find(szFuncName);
			if (pPyModule->m_FuncMap.end() != it)
			{
				PyObject* pv = it->second;
				if (pv)
				{
					PyObject* args = NULL;

					CStringA strArgsFormat = szArgsFormat;
					if (!strArgsFormat.IsEmpty())
					{
						//注意强制转换成元组、列表或字典
						va_list ap;
						va_start(ap, szArgsFormat);
						args = Py_VaBuildValue(szArgsFormat,ap);
						va_end(ap);
					}

					PyObject *pRet = PyEval_CallObject(pv, args);

#ifdef USE_CONSOLE
					if (!pRet)		PyErr_Print();
#endif
					
					PY_FREE(args);

					return pRet;
				}
			}
		}
	}

	return NULL;
}

PyObject * CPythonBase::ParseResult(PyObject *p, LPCSTR szKey, LPCSTR szArgsFormat, void *pRet)
{
	if (p)
	{
		PyObject* pValue = PyDict_GetItemString(p, szKey);
		if (pValue)
		{
			PyArg_Parse(pValue, szArgsFormat, pRet);
		}

		return pValue;
	}

	return NULL;
}

void CPythonBase::Init()
{
	//为未安装python环境用户设置python虚拟机环境
	wchar_t *szHomeDir = new wchar_t[MAX_PATH];
	assert(szHomeDir);
	if (szHomeDir)
	{
		ZeroMemory(szHomeDir,MAX_PATH);
		GetCurrentDirectory(MAX_PATH, szHomeDir);
		wcscat(szHomeDir, L"\\python35");
		Py_SetPythonHome(szHomeDir);
	}
	
	
	wchar_t szFileName[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szFileName, MAX_PATH);
	CString strExeFileName = szFileName;
	if (-1 != strExeFileName.ReverseFind('\\'))
	{
		strExeFileName = strExeFileName.Mid(strExeFileName.ReverseFind('\\') + 1);
	}
	Py_SetProgramName(strExeFileName.GetBuffer());  /* optional but recommended */

	//初始化python虚拟机
	Py_Initialize();
	assert(Py_IsInitialized());

#ifdef USE_CONSOLE
	AllocConsole();
	freopen("conout$", "w", stdout);
#endif
}
