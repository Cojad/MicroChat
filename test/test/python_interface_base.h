#pragma once
#include <map>
#include "python.h"
using namespace std;

//使用控制台显示log
#define USE_CONSOLE

#define PY_FREE(x)		if(x)	Py_DECREF(x)

class CPyModule
{
public:
	PyObject*						m_pModule = NULL;	//python模块
	map<CStringA, PyObject*>		m_FuncMap;			//函数表
};


class CPythonBase
{
public:
	CPythonBase();
	~CPythonBase();
	
	//载入模块
	PyObject *ImportModule(LPCSTR szModuleName);

	//注册python函数及调用参数
	BOOL RegisterPythonFunction(LPCSTR szModuleName, LPCSTR szFuncName);

	//执行Python函数
	PyObject *CallObject(LPCSTR szModuleName, LPCSTR szFuncName, LPCSTR szArgsFormat = NULL, ...);

protected:
	PyObject *ParseResult(PyObject *p, LPCSTR szKey, LPCSTR szArgsFormat, void *pRet);
private:
	//初始化Python虚拟机环境
	void Init();

	map<CStringA, CPyModule*>	m_map;
};

