/* threading.h - registration function for threading related routines
 *
 * NVGT - NonVisual Gaming Toolkit
 * Copyright (c) 2022-2026 Sam Tupy
 * https://nvgt.dev
 * This software is provided "as-is", without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 * 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
*/

#pragma once

class asIScriptEngine;

void RegisterThreading(asIScriptEngine* engine);
void script_threads_ending(); // The script's module is about to be discarded, see threading.cpp.
bool script_threads_stop(); // Ends what script threads run once the script's module is discarded, see threading.cpp.
bool script_threads_release_engine(); // Whether the script engine can be shut down, which no script thread uses any more then, see threading.cpp.
long poco_ms(unsigned int ms); // A script's uint milliseconds as the long Poco takes, see threading.cpp.
// A script's wait that nothing may ever end (a child process, a long network request, an event), for the time it lasts, see threading.cpp.
// Made on the waiting thread as the wait begins; ended() is asked between the wait's slices, and is true once exit() has been called since
// (on the main thread) or the script is over (on a script thread).
class script_wait {
	bool main;
	unsigned long long exits;
	bool aborting;
public:
	script_wait();
	bool ended();
	long slice() const; // The longest the wait lasts between two looks, in milliseconds.
};
