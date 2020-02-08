#ifndef _REPORTING_
#define _REPORTING_

#include <string>
#include <sstream> 
#include <iostream>
#include <fstream>
#include <locale>
#include <codecvt>
#include <map>

#include "Utils.hpp"
#include "json.hpp"

namespace Reporting{


	VOID Log(std::string func_name, std::map<std::string, std::string> arguments)
	{
		nlohmann::json j;
		std::ofstream log_file;

		j["event_time"] = Utils::GetCurrentDateTime();
		j["proc_name"] = Utils::GetCurrentProcessName();
		j["proc_id"] = std::to_string(GetCurrentProcessId());

		j["function"]["func_name"] = func_name;

		for(const auto &p : arguments)
			j["function"]["arguments"][p.first] = p.second;

		log_file.open("C:\\ProgramData\\Captain\\Reporting\\events.json", std::ios::out | std::ios::app);
		log_file << j << '\n';
		log_file.close();
	}

	VOID Init()
	{

		CHAR base_folder[] = "C:\\ProgramData\\Captain\\Reporting";
		if(CreateDirectoryA(base_folder, NULL)
			|| ERROR_ALREADY_EXISTS == GetLastError())
		{
			//
		}		
	}

}


#endif
