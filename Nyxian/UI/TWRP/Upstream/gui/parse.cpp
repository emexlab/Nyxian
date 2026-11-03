/*
        Copyright 2012 bigbiff/Dees_Troy TeamWin
        This file is part of TWRP/TeamWin Recovery Project.

        TWRP is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        TWRP is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with TWRP.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "objects.hpp"
std::string gui_parse_text(std::string str)
{
	// This function parses text for DataManager values encompassed by %value% in the XML
	// and string resources (%@resource_name%)
	size_t pos = 0, next, end;

	while (1)
	{
		next = str.find("{@", pos);
		if (next == std::string::npos)
			break;

		end = str.find('}', next + 1);
		if (end == std::string::npos)
			break;

		std::string var = str.substr(next + 2, (end - next) - 2);
		str.erase(next, (end - next) + 1);

		size_t default_loc = var.find('=', 0);
		std::string lookup;
		if (default_loc == std::string::npos) {
			str.insert(next, PageManager::GetResources()->FindString(var));
		} else {
			lookup = var.substr(0, default_loc);
			std::string default_string = var.substr(default_loc + 1, var.size() - default_loc - 1);
			str.insert(next, PageManager::GetResources()->FindString(lookup, default_string));
		}
	}
	pos = 0;
	while (1)
	{
		next = str.find('%', pos);
		if (next == std::string::npos)
			return str;

		end = str.find('%', next + 1);
		if (end == std::string::npos)
			return str;

		// We have a block of data
		std::string var = str.substr(next + 1, (end - next) - 1);
		str.erase(next, (end - next) + 1);

		if (next + 1 == end)
			str.insert(next, 1, '%');
		else
		{
			std::string value;
			if (var.size() > 0 && var[0] == '@') {
				// this is a string resource ("%@string_name%")
				value = PageManager::GetResources()->FindString(var.substr(1));
				str.insert(next, value);
			}
			else if (DataManager::GetValue(var, value) == 0)
				str.insert(next, value);
		}

		pos = next + 1;
	}
}

std::string gui_lookup(const std::string& resource_name, const std::string& default_value) {
	return PageManager::GetResources()->FindString(resource_name, default_value);
}

