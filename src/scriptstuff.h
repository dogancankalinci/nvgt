/* subscripting.h - angelscript subscripting implementation header and various scripting related routines
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

#include <string>
#include <angelscript.h>
#include "nvgt.h"

bool script_compiled();
void profiler_callback(asIScriptContext* ctx, void* obj);
void nvgt_line_callback(asIScriptContext* ctx, void* obj); // Every context's line callback (nvgt_angelscript.cpp): the debugger's, then profiler_callback and script_function_call_count_statement.
void script_function_call_count_statement(asIScriptContext* ctx); // Counts a statement towards the limits of the script_function.call()s running on this thread.
extern int g_GCMode;
void prepare_profiler();
void garbage_collect_action();
extern asIScriptFunction* profiler_last_func;
extern int profiler_current_line;
extern const char* profiler_current_section;
std::string get_call_stack();
std::string get_call_stack_ctx(asIScriptContext* ctx);
void pop_nested_state(asIScriptContext* ctx);
int execute_nested(asIScriptContext* ctx);
bool script_callbacks_stopped(asIScriptContext* ctx); // nvgt_angelscript.cpp: exit() was called since ctx (the context calling a registered function) began, so that function must run no more script callbacks.
asIScriptFunction* get_default_args_function(asIScriptFunction* func); // The function whose default arguments a call of func evaluates: for a delegate, its method's implementation.
void RegisterScriptstuff(asIScriptEngine* engine);
