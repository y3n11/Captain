#ifndef _UTILS_
#define _UTILS_

#include <Windows.h>

namespace Utils{

	std::string GetCurrentDateTime()
	{
		SYSTEMTIME _sys;
    	GetSystemTime(&_sys);
    	std::string _datetime = std::to_string(_sys.wMonth) + "/" 
    							+ std::to_string(_sys.wDay) + "/" 
    							+ std::to_string(_sys.wYear) + " " 
    							+ std::to_string(_sys.wHour) + ":" 
    							+ std::to_string(_sys.wMinute) + ":" 
    							+ std::to_string(_sys.wSecond) + ":" 
    							+ std::to_string(_sys.wMilliseconds);
		return _datetime;
	}

	std::string GetCurrentProcessName()
	{
	    CHAR szExeFileName[MAX_PATH];
    	GetModuleFileNameA(NULL, szExeFileName, MAX_PATH);
		return std::string(szExeFileName);
	}

	std::string WideStringToAscii(std::wstring _wstr)
	{
		using convert_type = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_type, wchar_t> converter;
		std::string ascii_msg = converter.to_bytes(_wstr);

		return ascii_msg;
	}
}


#endif