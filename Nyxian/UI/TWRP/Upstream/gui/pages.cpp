/*
	Copyright 2013 bigbiff/Dees_Troy TeamWin
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
#include "../twcommon.h"
#include "../NXTWRPBridge.hpp"
#include <cstring>
int tw_x_offset=0,tw_y_offset=0,tw_w_offset=0,tw_h_offset=0;
int ConvertStrToColor(std::string str, COLOR* color)
{
	// Set the default, solid black
	memset(color, 0, sizeof(COLOR));
	color->alpha = 255;

	// Translate variables
	DataManager::GetValue(str, str);

	// Look for some defaults
	if (str == "black")		return 0;
	else if (str == "white")	{ color->red = color->green = color->blue = 255; return 0; }
	else if (str == "red")		{ color->red = 255; return 0; }
	else if (str == "green")	{ color->green = 255; return 0; }
	else if (str == "blue")		{ color->blue = 255; return 0; }

	// At this point, we require an RGB(A) color
	if (str[0] != '#')
		return -1;

	str.erase(0, 1);

	int result;
	if (str.size() >= 8) {
		// We have alpha channel
		string alpha = str.substr(6, 2);
		result = strtol(alpha.c_str(), NULL, 16);
		color->alpha = result & 0x000000FF;
		str.resize(6);
		result = strtol(str.c_str(), NULL, 16);
		color->red = (result >> 16) & 0x000000FF;
		color->green = (result >> 8) & 0x000000FF;
		color->blue = result & 0x000000FF;
	} else {
		result = strtol(str.c_str(), NULL, 16);
		color->red = (result >> 16) & 0x000000FF;
		color->green = (result >> 8) & 0x000000FF;
		color->blue = result & 0x000000FF;
	}
	return 0;
}

// Helper APIs
xml_node<>* FindNode(xml_node<>* parent, const char* nodename, int depth /* = 0 */)
{
	if (!parent)
		return NULL;

	xml_node<>* child = parent->first_node(nodename);
	if (child)
		return child;

	if (depth == 10) {
		LOGERR("Too many style loops detected.\n");
		return NULL;
	}

	xml_node<>* style = parent->first_node("style");
	if (style) {
		while (style) {
			if (!style->first_attribute("name")) {
				LOGERR("No name given for style.\n");
				continue;
			} else {
				std::string name = style->first_attribute("name")->value();
				xml_node<>* node = PageManager::FindStyle(name);

				if (node) {
					// We found the style that was named
					xml_node<>* stylenode = FindNode(node, nodename, depth + 1);
					if (stylenode)
						return stylenode;
				}
			}
			style = style->next_sibling("style");
		}
	} else {
		// Search for stylename in the parent node <object type="foo" style="foo2">
		xml_attribute<>* attr = parent->first_attribute("style");
		// If no style is found anywhere else and the node wasn't found in the object itself
		// as a special case we will search for a style that uses the same style name as the
		// object type, so <object type="button"> would search for a style named "button"
		if (!attr)
			attr = parent->first_attribute("type");
		// if there's no attribute type, the object type must be the element name
		std::string stylename = attr ? attr->value() : parent->name();
		xml_node<>* node = PageManager::FindStyle(stylename);
		if (node) {
			xml_node<>* stylenode = FindNode(node, nodename, depth + 1);
			if (stylenode)
				return stylenode;
		}
	}
	return NULL;
}

std::string LoadAttrString(xml_node<>* element, const char* attrname, const char* defaultvalue)
{
	if (!element)
		return defaultvalue;

	xml_attribute<>* attr = element->first_attribute(attrname);
	return attr ? attr->value() : defaultvalue;
}

int LoadAttrInt(xml_node<>* element, const char* attrname, int defaultvalue)
{
	string value = LoadAttrString(element, attrname);
	// resolve variables
	DataManager::GetValue(value, value);
	return value.empty() ? defaultvalue : atoi(value.c_str());
}

int LoadAttrIntScaleX(xml_node<>* element, const char* attrname, int defaultvalue)
{
	return scale_theme_x(LoadAttrInt(element, attrname, defaultvalue));
}

int LoadAttrIntScaleY(xml_node<>* element, const char* attrname, int defaultvalue)
{
	return scale_theme_y(LoadAttrInt(element, attrname, defaultvalue));
}

COLOR LoadAttrColor(xml_node<>* element, const char* attrname, bool* found_color, COLOR defaultvalue)
{
	string value = LoadAttrString(element, attrname);
	*found_color = !value.empty();
	// resolve variables
	DataManager::GetValue(value, value);
	COLOR ret = defaultvalue;
	if (ConvertStrToColor(value, &ret) == 0)
		return ret;
	else
		return defaultvalue;
}

COLOR LoadAttrColor(xml_node<>* element, const char* attrname, COLOR defaultvalue)
{
	bool found_color = false;
	return LoadAttrColor(element, attrname, &found_color, defaultvalue);
}

FontResource* LoadAttrFont(xml_node<>* element, const char* attrname)
{
	std::string name = LoadAttrString(element, attrname, "");
    auto font=PageManager::GetResources()->FindFont(name);
    return font?font:PageManager::GetResources()->FindFont("font_m");
}

ImageResource* LoadAttrImage(xml_node<>* element, const char* attrname)
{
	std::string name = LoadAttrString(element, attrname, "");
	if (name.empty())
		return NULL;
	else
		return PageManager::GetResources()->FindImage(name);
}

AnimationResource* LoadAttrAnimation(xml_node<>* element, const char* attrname)
{
	std::string name = LoadAttrString(element, attrname, "");
	if (name.empty())
		return NULL;
	else
		return PageManager::GetResources()->FindAnimation(name);
}

bool LoadPlacement(xml_node<>* node, int* x, int* y, int* w /* = NULL */, int* h /* = NULL */, Placement* placement /* = NULL */)
{
	if (!node)
		return false;

	if (node->first_attribute("x"))
		*x = LoadAttrIntScaleX(node, "x") + tw_x_offset;

	if (node->first_attribute("y"))
		*y = LoadAttrIntScaleY(node, "y") + tw_y_offset;

	if (w && node->first_attribute("w"))
		*w = LoadAttrIntScaleX(node, "w");

	if (h && node->first_attribute("h"))
		*h = LoadAttrIntScaleY(node, "h");

	if (placement && node->first_attribute("placement"))
		*placement = (Placement) LoadAttrInt(node, "placement");

	return true;
}

int ActionObject::SetActionPos(int x, int y, int w, int h)
{
	if (x < 0 || y < 0)
		return -1;

	mActionX = x;
	mActionY = y;
	if (w || h)
	{
		mActionW = w;
		mActionH = h;
	}
	return 0;
}

Page::Page(xml_node<>* page, std::vector<xml_node<>*> *templates)
{
	mTouchStart = NULL;

	// We can memset the whole structure, because the alpha channel is ignored
	memset(&mBackground, 0, sizeof(COLOR));

	// With NULL, we make a console-only display
	if (!page)
	{
		mName = "console";

		GUIConsole* element = new GUIConsole(NULL);
		mRenders.push_back(element);
		mActions.push_back(element);
		return;
	}

	if (page->first_attribute("name"))
		mName = page->first_attribute("name")->value();
	else
	{
		LOGERR("No page name attribute found!\n");
		return;
	}

	LOGINFO("Loading page %s\n", mName.c_str());

	// This is a recursive routine for template handling
	ProcessNode(page, templates, 0);
}

Page::~Page()
{
	for (std::vector<GUIObject*>::iterator itr = mObjects.begin(); itr != mObjects.end(); ++itr)
		delete *itr;
}

bool Page::ProcessNode(xml_node<>* page, std::vector<xml_node<>*> *templates, int depth)
{
	if (depth == 10)
	{
		LOGERR("Page processing depth has exceeded 10. Failing out. This is likely a recursive template.\n");
		return false;
	}

	for (xml_node<>* child = page->first_node(); child; child = child->next_sibling())
	{
		std::string type = child->name();

		if (type == "background") {
			mBackground = LoadAttrColor(child, "color", COLOR(0,0,0,0));
			continue;
		}

		if (type == "object") {
			// legacy format : <object type="...">
			xml_attribute<>* attr = child->first_attribute("type");
			type = attr ? attr->value() : "*unspecified*";
		}

		if (type == "text")
		{
			GUIText* element = new GUIText(child);
			mObjects.push_back(element);
			mRenders.push_back(element);
			mActions.push_back(element);
		}
		else if (type == "image")
		{
			GUIImage* element = new GUIImage(child);
			mObjects.push_back(element);
			mRenders.push_back(element);
		}
		else if (type == "fill")
		{
			GUIFill* element = new GUIFill(child);
			mObjects.push_back(element);
			mRenders.push_back(element);
		}
		else if (type == "action")
		{
			GUIAction* element = new GUIAction(child);
			mObjects.push_back(element);
			mActions.push_back(element);
		}
		else if (type == "console")
		{
			GUIConsole* element = new GUIConsole(child);
			mObjects.push_back(element);
			mRenders.push_back(element);
			mActions.push_back(element);
		}
		else if (type == "terminal")
		{
			GUIObject* element = nx_twrp_terminal(child);
			mObjects.push_back(element);
			mRenders.push_back(dynamic_cast<RenderObject*>(element));
			mActions.push_back(dynamic_cast<ActionObject*>(element));
			mInputs.push_back(dynamic_cast<InputObject*>(element));
		}

		else if (type == "button")
		{
			GUIObject* element = nx_twrp_button(child);
			mObjects.push_back(element);
			mRenders.push_back(dynamic_cast<RenderObject*>(element));
			mActions.push_back(dynamic_cast<ActionObject*>(element));
		}




		else if (type == "checkbox") {
            GUIObject* element=nx_twrp_checkbox(child);mObjects.push_back(element);
            mRenders.push_back(dynamic_cast<RenderObject*>(element));mActions.push_back(dynamic_cast<ActionObject*>(element));
        }
		else if (type == "slider")
		{
			GUIObject* element = nx_twrp_slider(child);
			mObjects.push_back(element);
			mRenders.push_back(dynamic_cast<RenderObject*>(element));
			mActions.push_back(dynamic_cast<ActionObject*>(element));
		}






        else if (type == "nyxiansettingslist" || type == "slidervalue") {
            GUIObject* element=type=="slidervalue"?nx_twrp_slidervalue(child):nx_twrp_settingslist(child);
            mObjects.push_back(element);mRenders.push_back(dynamic_cast<RenderObject*>(element));mActions.push_back(dynamic_cast<ActionObject*>(element));
        }
        else if (type == "progressbar") {
            GUIProgressBar* element=new GUIProgressBar(child);mObjects.push_back(element);mRenders.push_back(element);
        }
        else if (type == "keyboard") {
            GUIObject* element=nx_twrp_keyboard(child);mObjects.push_back(element);
            mRenders.push_back(dynamic_cast<RenderObject*>(element));mActions.push_back(dynamic_cast<ActionObject*>(element));
        }
        else if (type == "input") {
            GUIObject* element=nx_twrp_input(child);mObjects.push_back(element);
            mRenders.push_back(dynamic_cast<RenderObject*>(element));mActions.push_back(dynamic_cast<ActionObject*>(element));mInputs.push_back(dynamic_cast<InputObject*>(element));
        }
        else if (type == "fileselector") {
            GUIObject* element=nx_twrp_fileselector(child);mObjects.push_back(element);
            mRenders.push_back(dynamic_cast<RenderObject*>(element));mActions.push_back(dynamic_cast<ActionObject*>(element));
        }
		else if (type == "nyxianmenu") {
            GUIObject* element = nx_twrp_menu(child);
            mObjects.push_back(element);
            mRenders.push_back(dynamic_cast<RenderObject*>(element));
            mActions.push_back(dynamic_cast<ActionObject*>(element));
        }
		else if (type == "textbox")
		{
			GUITextBox* element = new GUITextBox(child);
			mObjects.push_back(element);
			mRenders.push_back(element);
			mActions.push_back(element);
		}
		else if (type == "template")
		{
			if (!templates || !child->first_attribute("name"))
			{
				LOGERR("Invalid template request.\n");
			}
			else
			{
				std::string name = child->first_attribute("name")->value();
				xml_node<>* node;
				bool node_found = false;

				// We need to find the correct template
				for (std::vector<xml_node<>*>::iterator itr = templates->begin(); itr != templates->end(); itr++) {
					node = (*itr)->first_node("template");

					while (node)
					{
						if (!node->first_attribute("name"))
							continue;

						if (name == node->first_attribute("name")->value())
						{
							if (!ProcessNode(node, templates, depth + 1))
								return false;
							else {
								node_found = true;
								break;
							}
						}
						if (node_found)
							break;
						node = node->next_sibling("template");
					}
					if (node_found) break; // First matching theme template overrides stock.
				}
			}
		}
		else
		{
			LOGERR("Unknown object type: %s.\n", type.c_str());
		}
	}
	return true;
}

int Page::Render(void)
{
	// Render background
	gr_color(mBackground.red, mBackground.green, mBackground.blue, mBackground.alpha);
	gr_fill(0, 0, gr_fb_width(), gr_fb_height());

	// Render remaining objects
	std::vector<RenderObject*>::iterator iter;
	for (iter = mRenders.begin(); iter != mRenders.end(); iter++)
	{
		if ((*iter)->Render())
			LOGERR("A render request has failed.\n");
	}
	return 0;
}

int Page::Update(void)
{
	int retCode = 0;

	std::vector<RenderObject*>::iterator iter;
	for (iter = mRenders.begin(); iter != mRenders.end(); iter++)
	{
		int ret = (*iter)->Update();
		if (ret < 0)
			LOGERR("An update request has failed.\n");
		else if (ret > retCode)
			retCode = ret;
	}

	return retCode;
}

int Page::NotifyTouch(TOUCH_STATE state, int x, int y)
{
	// By default, return 1 to ignore further touches if nobody is listening
	int ret = 1;

	// Don't try to handle a lack of handlers
	if (mActions.size() == 0)
		return ret;

	// We record mTouchStart so we can pass all the touch stream to the same handler
	if (state == TOUCH_START)
	{
		std::vector<ActionObject*>::reverse_iterator iter;
		// We work backwards, from top-most element to bottom-most element
		for (iter = mActions.rbegin(); iter != mActions.rend(); iter++)
		{
			if ((*iter)->IsInRegion(x, y))
			{
				mTouchStart = (*iter);
				ret = mTouchStart->NotifyTouch(state, x, y);
				if (ret >= 0)
					break;
				mTouchStart = NULL;
			}
		}
	}
	else if (state == TOUCH_RELEASE && mTouchStart != NULL)
	{
		ret = mTouchStart->NotifyTouch(state, x, y);
		mTouchStart = NULL;
	}
	else if ((state == TOUCH_DRAG || state == TOUCH_HOLD || state == TOUCH_REPEAT) && mTouchStart != NULL)
	{
		ret = mTouchStart->NotifyTouch(state, x, y);
	}
	return ret;
}

int Page::NotifyKey(int key, bool down)
{
	std::vector<ActionObject*>::reverse_iterator iter;

	int ret = 1;
	// We work backwards, from top-most element to bottom-most element
	for (iter = mActions.rbegin(); iter != mActions.rend(); iter++)
	{
		ret = (*iter)->NotifyKey(key, down);
		if (ret == 0)
			return 0;
		if (ret < 0) {
			LOGERR("An action handler has returned an error\n");
			ret = 1;
		}
	}
	return ret;
}

int Page::NotifyCharInput(int ch)
{
	std::vector<InputObject*>::reverse_iterator iter;

	// We work backwards, from top-most element to bottom-most element
	for (iter = mInputs.rbegin(); iter != mInputs.rend(); iter++)
	{
		int ret = (*iter)->NotifyCharInput(ch);
		if (ret == 0)
			return 0;
		else if (ret < 0)
			LOGERR("A char input handler has returned an error\n");
	}
	return 1;
}

int Page::SetKeyBoardFocus(int inFocus)
{
	std::vector<InputObject*>::reverse_iterator iter;

	// We work backwards, from top-most element to bottom-most element
	for (iter = mInputs.rbegin(); iter != mInputs.rend(); iter++)
	{
		int ret = (*iter)->SetInputFocus(inFocus);
		if (ret == 0)
			return 0;
		else if (ret < 0)
			LOGERR("An input focus handler has returned an error\n");
	}
	return 1;
}

void Page::SetPageFocus(int inFocus)
{
	// Render remaining objects
	std::vector<RenderObject*>::iterator iter;
	for (iter = mRenders.begin(); iter != mRenders.end(); iter++)
		(*iter)->SetPageFocus(inFocus);

	return;
}

int Page::NotifyVarChange(std::string varName, std::string value)
{
	std::vector<GUIObject*>::iterator iter;
	for (iter = mObjects.begin(); iter != mObjects.end(); ++iter)
	{
		if ((*iter)->NotifyVarChange(varName, value))
			LOGERR("An action handler errored on NotifyVarChange.\n");
	}
	return 0;
}


