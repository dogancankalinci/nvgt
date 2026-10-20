/* scriptstuff.cpp - angelscript subscripting implementation code and various scripting related routines
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

#define NOMINMAX
#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>
#ifdef _WIN32
	#include <windows.h>
#endif
#include <obfuscate.h>
#include <Poco/Util/Application.h>
#include <Poco/Exception.h>
#include <Poco/Format.h>
#include <Poco/Path.h>
#include <Poco/Thread.h>
#include <scriptany.h>
#include <scriptarray.h>
#include <scriptdictionary.h>
#include <scripthelper.h>
#include "datastreams.h"
#include "nvgt.h"
#include "scriptstuff.h"
#include "timestuff.h"

// The seemingly pointless few lines of code that follow are just a bit of structure that can be used to aid in some types of debugging if needed. Extra code can be added temporarily in the line callback that sets any needed info in the g_DebugInfo string which can easily be read by a c debugger.
std::string g_DebugInfo;
void debug_callback(asIScriptContext* ctx, void* obj) {
}

int g_GCMode = 2;
Poco::Thread* g_GCThread = nullptr;
asQWORD g_GCAutoFullTime = ticks();
unsigned int g_GCAutoFrequency = 300000;
void garbage_collect(bool full = true) {
	if (!full && g_GCMode < 3)
		g_ScriptEngine->GarbageCollect(asGC_ONE_STEP | asGC_DETECT_GARBAGE);
	else if (full && g_GCMode < 3)
		g_ScriptEngine->GarbageCollect(asGC_FULL_CYCLE);
	else if (full && g_GCMode == 3)
		g_GCAutoFullTime = 0;
}
void garbage_collect_action() {
	g_ScriptEngine->GarbageCollect(asGC_ONE_STEP);
	if (ticks() - g_GCAutoFullTime > g_GCAutoFrequency) {
		g_ScriptEngine->GarbageCollect(asGC_ONE_STEP);
		g_GCAutoFullTime = ticks();
	}
}
void garbage_collect_thread(void* user) {
	Poco::Thread::sleep(10);
	while (g_GCMode == 3) {
		Poco::Thread::sleep(5);
		garbage_collect_action();
	}
	delete g_GCThread;
	g_GCThread = nullptr;
}
int get_garbage_collect_mode() {
	return g_GCMode;
}
bool set_garbage_collect_mode(int m) {
	if (m < 1 || m > 3) return false;
	if (m == 3 && !g_GCThread) {
		g_GCThread = new Poco::Thread;
		if (!g_GCThread)
			return false;
		g_GCThread->start(garbage_collect_thread);
	}
	g_GCMode = m;
	return true;
}
unsigned int get_garbage_collect_auto_frequency() {
	return g_GCAutoFrequency;
}
bool set_garbage_collect_auto_frequency(unsigned int freq) {
	if (freq < 2000 || freq > 86400000) return false;
	g_GCAutoFrequency = freq;
	return true;
}

std::map<asIScriptFunction*, std::chrono::high_resolution_clock::time_point> profiler_cache;
bool is_profiling;
std::chrono::high_resolution_clock::time_point profiler_ticks;
std::chrono::high_resolution_clock::time_point profiler_start = std::chrono::high_resolution_clock::now();
asIScriptFunction* profiler_last_func;
int profiler_current_line = 0;
const char* profiler_current_section = NULL;

void profiler_callback(asIScriptContext* ctx, void* obj) {
	if (!is_profiling) return;
	int col;
	profiler_current_line = ctx->GetLineNumber(0, &col, &profiler_current_section);
	/*
	const char* section;
	int line, col;
	line=ctx->GetLineNumber(0, &col, &section);
	char tmp[MAX_PATH];
	snprintf(tmp, MAX_PATH, "%s %d\r\n", section, line);
	FILE* f=fopen("debug.txt", "ab");
	fputs(tmp, f);
	fclose(f);
	*/
	auto t = std::chrono::high_resolution_clock::now();
	asIScriptFunction* sfunc = ctx->GetSystemFunction();
	asIScriptFunction* func = (sfunc != NULL ? sfunc : ctx->GetFunction());
	auto elapsed = t - profiler_ticks;
	profiler_ticks = t;
	if (func == profiler_last_func) {
		profiler_cache[func] += elapsed;;
		return;
	}
	if (profiler_last_func != NULL) {
		std::map<asIScriptFunction*, std::chrono::high_resolution_clock::time_point>::iterator it = profiler_cache.find(func);
		if (it == profiler_cache.end())
			profiler_cache[func] = std::chrono::high_resolution_clock::time_point(profiler_start + elapsed);
		else
			profiler_cache[func] += elapsed;
	}
	profiler_last_func = func;
}
void reset_profiler() {
	profiler_cache.clear();
	profiler_ticks = std::chrono::high_resolution_clock::now();
	profiler_start = std::chrono::high_resolution_clock::now();
	profiler_last_func = NULL;
	prepare_profiler();
}
void prepare_profiler() {
	if (!is_profiling) return;
	asIScriptContext* ctx = asGetActiveContext();
	if (!ctx) return;
	profiler_last_func = ctx->GetFunction();
	profiler_cache[profiler_last_func] = profiler_start;
}
void start_profiling() {
	if (is_profiling) return;
	asIScriptContext* ctx = asGetActiveContext();
	if (!ctx) return;
	is_profiling = true;
	reset_profiler();
}
void stop_profiling() {
	asIScriptContext* ctx = asGetActiveContext();
	if (!is_profiling || !ctx)
		return;
	is_profiling = false;
}
static bool profiler_results_sort(asIScriptFunction* f1, asIScriptFunction* f2) {
	return profiler_cache[f1] > profiler_cache[f2];
}
std::string generate_profile(bool reset = true) {
	if (profiler_cache.size() < 1) return "";
	std::vector<asIScriptFunction*> results;
	results.reserve(profiler_cache.size());
	for (auto const& i : profiler_cache)
		results.push_back(i.first);
	std::sort(results.begin(), results.end(), profiler_results_sort);
	int size = results.size();
	char tmp[128];
	unsigned int total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - profiler_start).count();
	snprintf(tmp, 128, "total functions called: %d\r\ntotal execution time: %ums\r\n\r\n", size, total_ms);
	std::string output(tmp);
	for (int i = 0; i < size; i++) {
		char text[4096];
		if (!results[i]) continue;
		const char* decl = results[i]->GetDeclaration(true, true, true);
		float ms = std::chrono::duration_cast<std::chrono::milliseconds>(profiler_cache[results[i]] - profiler_start).count();
		float p = (ms / total_ms) * 100.0;
		snprintf(text, 4096, "%s: %.0fms (%.3f%%)\r\n", decl, ms, p);
		output += text;
	}
	if (reset) reset_profiler();
	return output;
}

std::string get_call_stack_ctx(asIScriptContext* ctx) {
	asUINT size = ctx->GetCallstackSize();
	char tmp[4096];
	snprintf(tmp, 4096, "Call stack size: %d\r\n\r\n", size);
	std::string stack = tmp;
	for (asUINT i = 0; i < size; i++) {
		const char* section = nullptr;
		int line = 0, col = 0;
		asIScriptFunction* func = ctx->GetFunction(i);
		line = ctx->GetLineNumber(i, &col, &section);
		if (func) {
			const char* decl = func->GetDeclaration();
			if (!decl) decl = "(unknown)";
			if (!section) section = "(unknown)";
			snprintf(tmp, 4096, "Function: %s\r\nFile: %s\r\n", decl, section);
		} else {
			if (!section) section = "(unknown)";
			snprintf(tmp, 4096, "Function: (unknown)\r\nFile: %s\r\n", section);
		}
		stack += tmp;
		if (line) {
			snprintf(tmp, 4096, "Line: %d (%d)\r\n", line, col);
			stack += tmp;
		}
		stack += "\r\n";
	}
	return stack;
}
// Ends a script call made as a nested call of the script's own context (PushState()). exit() aborts the script's context, so a
// callback calling it ends the nested execution as aborted, which consumes the abort; it was dropped here, and the script
// went on running after exit() (with the manager no longer holding its context, see ExecuteScript). The abort is passed
// on to the interrupted execution, as AngelScript's own nested calls do.
void pop_nested_state(asIScriptContext* ctx) {
	bool aborted = ctx->GetState() == asEXECUTION_ABORTED;
	ctx->PopState();
	if (aborted) ctx->Abort();
}
// Runs a script callback for a registered function, which is usually a nested call of the script's own context (the one
// calling that function). A nested execution can't be left suspended: the context manager's sleep() or yield() in the
// callback suspended it, and the nested state was then popped while suspended, which left the callback's frames on the call
// stack where PopState() expects the nested call's marker and restored the interrupted execution from them (a crash once the
// callback had called another function). It is resumed until it ends, as AngelScript's own nested calls are, so such a sleep()
// or yield() returns at once.
int execute_nested(asIScriptContext* ctx) {
	int r;
	while ((r = ctx->Execute()) == asEXECUTION_SUSPENDED) {}
	return r;
}
std::string get_call_stack() {
	return get_call_stack_ctx(asGetActiveContext());
}
int get_call_stack_size() {
	asIScriptContext* ctx = asGetActiveContext();
	return ctx->GetCallstackSize();
}
std::string get_script_current_function() {
	asIScriptContext* ctx = asGetActiveContext();
	asIScriptFunction* func = ctx->GetFunction();
	if (!func)
		return "";
	return func->GetDeclaration();
}
std::string get_script_current_file() {
	asIScriptContext* ctx = asGetActiveContext();
	const char* section = NULL;
	ctx->GetLineNumber(0, NULL, &section);
	if (section) return std::string(section);
	return "";
}
int get_script_current_line() {
	asIScriptContext* ctx = asGetActiveContext();
	return ctx->GetLineNumber();
}
std::string get_script_executable() {
	return Poco::Util::Application::instance().config().getString("application.path");
}
std::string get_script_path() {
	if (!script_compiled()) return g_scriptpath;
	return Poco::Path(get_script_executable()).makeAbsolute().makeParent().toString();
}
std::string get_function_signature(void* function, int type_id) {
	asIScriptContext* ctx = asGetActiveContext();
	if (!ctx) return "";
	asIScriptEngine* engine = ctx ? ctx->GetEngine() : g_ScriptEngine;
	asITypeInfo* t = engine->GetTypeInfoById(type_id);
	asIScriptFunction* sig = t? t->GetFuncdefSignature() : nullptr;
	if (!sig) {
		ctx->SetException("not a function");
		return "";
	}
	if (type_id & asTYPEID_OBJHANDLE) {
		asIScriptFunction* handle = *(asIScriptFunction**)function;
		if (!handle) {
			ctx->SetException("null function handle");
			return "";
		}
		return handle->GetDeclaration();
	}
	else
		return sig->GetDeclaration();
}
bool script_compiled() {
	#ifdef NVGT_STUB
	return true;
	#else
	return false;
	#endif
}
void dump_angelscript_engine_configuration(datastream* output) {
	#ifndef NVGT_STUB
	if (!output || !output->get_ostr()) return;
	WriteConfigToStream(g_ScriptEngine, *output->get_ostr());
	#endif
}
void script_assert(bool expr, const std::string& failtext = "") {
	if (!expr) throw Poco::AssertionViolationException(failtext);
}

void script_message_callback(const asSMessageInfo* msg, void* param) {
	if (!param)
		return;
	CScriptArray* messages = (CScriptArray*)param;
	const char* type = "ERROR: ";
	if (msg->type == asMSGTYPE_WARNING)
		type = "WARNING: ";
	else if (msg->type == asMSGTYPE_INFORMATION)
		type = "INFO: ";
	char buffer[8192];
	snprintf(buffer, 8192, "file: %s\r\nline: %d (%d)\r\n%s: %s\r\n\r\n", msg->section, msg->row, msg->col, type, msg->message);
	std::string buffer_str = buffer; // Damn it g++
	if (msg->type == asMSGTYPE_ERROR)
		messages->InsertLast(&buffer_str);
}
struct script_function_call_data {
	int max_statement_count;
	int current_statement_count;
	bool exceeded; // The limit ended the call: aborted rather than suspended, as a nested call can't be left suspended (see execute_nested), and not passed on to the caller.
	asIScriptContext* ctx; // The context running the call.
	script_function_call_data* outer; // The call on this thread that this one was made in, whose statements this one's are too.
};
// The innermost script_function.call() running on this thread. AngelScript can't tell what line callback a context has, so a call made in another put back nvgt_line_callback when it returned, and the outer call's statement limit stopped counting.
static thread_local script_function_call_data* g_script_function_call = nullptr;
struct script_function_call_scope {
	script_function_call_data& data;
	script_function_call_scope(script_function_call_data& data) : data(data) { g_script_function_call = &data; }
	~script_function_call_scope() { g_script_function_call = data.outer; }
};
// Stores a value of script_function.call()'s result. A number is kept as an int64 or a double, as the script's own dictionary::set() keeps it, since get() converts only from those: the result of a function returning an int, a float or another size, kept under its own type, couldn't be read back by any get().
static void set_call_result(CScriptDictionary* d, const std::string& key, void* value, int type_id) {
	switch (type_id) {
		case asTYPEID_INT8: d->Set(key, asINT64(*(asINT8*)value)); break;
		case asTYPEID_INT16: d->Set(key, asINT64(*(asINT16*)value)); break;
		case asTYPEID_INT32: d->Set(key, asINT64(*(int*)value)); break;
		case asTYPEID_UINT8: d->Set(key, asINT64(*(asBYTE*)value)); break;
		case asTYPEID_UINT16: d->Set(key, asINT64(*(asWORD*)value)); break;
		case asTYPEID_UINT32: d->Set(key, asINT64(*(asDWORD*)value)); break;
		case asTYPEID_UINT64: d->Set(key, asINT64(*(asQWORD*)value)); break;
		case asTYPEID_FLOAT: d->Set(key, double(*(float*)value)); break;
		default: d->Set(key, value, type_id);
	}
}
// Releases what script_function.call() made for reference parameters, once the function can no longer use it.
static void release_made_arguments(std::vector<std::pair<void*, asITypeInfo*>>& objects, std::vector<std::pair<void**, asITypeInfo*>>& handles) {
	for (auto& o : objects) g_ScriptEngine->ReleaseScriptObject(o.first, o.second);
	for (auto& h : handles) {
		if (*h.first) g_ScriptEngine->ReleaseScriptObject(*h.first, h.second);
	}
	objects.clear();
	handles.clear();
}
void script_function_line_callback(asIScriptContext* ctx, script_function_call_data* data);
CScriptDictionary* script_function_call(asIScriptFunction* func, CScriptDictionary* args, CScriptArray* errors = NULL, int max_statement_count = 0) {
	std::string failure_reason = "";
	std::string callstack1 = "";
	std::string callstack2 = "";
	g_ScriptEngine->SetMessageCallback(asFUNCTION(script_message_callback), errors, asCALL_CDECL);
	script_function_call_data call_data {max_statement_count, 0, false, nullptr, g_script_function_call};
	// The values passed to reference parameters, which the arguments point to, so they last until the call returns (8 bytes hold any primitive or a handle).
	std::vector<asQWORD> ref_values(func->GetParamCount());
	// What reference parameters are given, released once the call is over: objects made here (a copy of an argument of a value type, a default value, room for an &out result) or held here (an argument of a reference type), and the handles held in ref_values.
	std::vector<std::pair<void*, asITypeInfo*>> made_objects;
	std::vector<std::pair<void**, asITypeInfo*>> made_handles;
	// Where each &out or &inout argument's value is once the function has returned (parameter index, address, type id), given back in the result under the argument's number.
	std::vector<std::tuple<asUINT, void*, int>> out_args;
	asIScriptContext* defCtx = nullptr; // Evaluates default arguments, as async does.
	asIScriptContext* ACtx = asGetActiveContext();
	bool new_context = ACtx == NULL || ACtx->PushState() < 0;
	asIScriptContext* ctx = (new_context ? g_ScriptEngine->RequestContext() : ACtx);
	if (!ctx) {
		failure_reason = "ERROR: Failed to acquire context.";
		goto failure;
	}
	if (ctx->Prepare(func) < 0) {
		failure_reason = "ERROR: Failed to prepare context.";
		goto failure;
	}
	asUINT param_count;
	param_count = func->GetParamCount();
	for (asUINT p = 0; p < param_count; p++) {
		int arg_type_id;
		asDWORD arg_tmods;
		const char* arg_default = nullptr;
		if (func->GetParam(p, &arg_type_id, &arg_tmods, nullptr, &arg_default) < 0) {
			failure_reason = "ERROR: Can't read parameter ";
			failure_reason += std::to_string(p + 1);
			goto failure;
		}
		// The argument of a reference parameter is the address of the value: a copy in ref_values or made here, or an object held here (see below). The value was put there instead: the function took a number for an address (a crash, and with int64 &out a write through it), int &in and float &in were refused by SetArgDWord()/SetArgFloat() and the call failed, and a handle reference got the object's address where a handle's belongs.
		bool by_ref;
		by_ref = (arg_tmods & asTM_INOUTREF) != 0;
		bool is_value_object;
		is_value_object = (arg_type_id & asTYPEID_MASK_OBJECT) && !(arg_type_id & asTYPEID_OBJHANDLE);
		if (args) {
			CScriptDictionary::CIterator k = args->find(std::to_string(p + 1));
			if (k != args->end()) {
				void* arg_value = ctx->GetAddressOfArg(p);
				if (!arg_value) {
					failure_reason = "ERROR: Trying to pass too many arguments.";
					goto failure;
				}
				if ((arg_type_id & asTYPEID_MASK_OBJECT)) {
					int value_type_id = k.GetTypeId();
					const void* o = k.GetAddressOfValue();
					void* obj = (value_type_id & asTYPEID_OBJHANDLE)? *(void**)o : (void*)o;
					asITypeInfo* value_type = g_ScriptEngine->GetTypeInfoById(value_type_id);
					asITypeInfo* arg_type = g_ScriptEngine->GetTypeInfoById(arg_type_id);
					bool compatible = value_type && arg_type && (value_type == arg_type || value_type->DerivesFrom(arg_type) || value_type->Implements(arg_type));
					if (!compatible || (!obj && !(arg_type_id & asTYPEID_OBJHANDLE))) {
						failure_reason = "ERROR: Type mismatch for parameter ";
						failure_reason += std::to_string(p + 1);
						goto failure;
					}
					// A reference parameter never gets the dictionary's own value: the function can reach the dictionary (when it is passed a handle to it, or a global holds one) and empty or change it, which freed a value the function was still using (a value type lives inside the dictionary, and the dictionary may hold the only reference to an object), and an assignment to a handle parameter, even an &in one, released the dictionary's object behind its back. A handle goes in ref_values, a value type is copied, and an object of a reference type is the object itself, each held by call() until the call is over. The result of an &out or &inout one is read from there.
					if (by_ref && (arg_type_id & asTYPEID_OBJHANDLE)) {
						*(void**)&ref_values[p] = obj;
						if (obj) g_ScriptEngine->AddRefScriptObject(obj, value_type);
						made_handles.emplace_back((void**)&ref_values[p], arg_type); // Released as the parameter's type, which is what the function may leave there.
						ctx->SetArgAddress(p, &ref_values[p]);
						if (arg_tmods & asTM_OUTREF) out_args.emplace_back(p, &ref_values[p], arg_type_id);
					} else if (by_ref && (arg_type->GetFlags() & asOBJ_VALUE)) {
						void* copy = g_ScriptEngine->CreateScriptObjectCopy(obj, arg_type);
						if (!copy) {
							failure_reason = "ERROR: Can't copy the value of parameter ";
							failure_reason += std::to_string(p + 1);
							goto failure;
						}
						made_objects.emplace_back(copy, arg_type);
						ctx->SetArgAddress(p, copy);
						if (arg_tmods & asTM_OUTREF) out_args.emplace_back(p, copy, arg_type_id);
					} else if (by_ref) {
						g_ScriptEngine->AddRefScriptObject(obj, value_type);
						made_objects.emplace_back(obj, value_type);
						ctx->SetArgAddress(p, obj);
						if (arg_tmods & asTM_OUTREF) {
							// Given back as it was given: a handle to the object, or a copy of it.
							if (value_type_id & asTYPEID_OBJHANDLE) {
								*(void**)&ref_values[p] = obj;
								out_args.emplace_back(p, &ref_values[p], value_type_id);
							} else out_args.emplace_back(p, obj, value_type_id);
						}
					} else ctx->SetArgObject(p, obj);
				} else if (by_ref) {
					void* value = &ref_values[p];
					asINT64 ival;
					double dval;
					if (k.GetValue(value, arg_type_id)) ;
					else if (arg_type_id == asTYPEID_INT32 && k.GetValue(ival)) *(int*)value = int(ival);
					else if (arg_type_id == asTYPEID_FLOAT && k.GetValue(dval)) *(float*)value = float(dval);
					else if (arg_type_id == asTYPEID_BOOL && k.GetValue(ival)) *(bool*)value = ival != 0;
					else {
						failure_reason = "ERROR: Type mismatch for parameter ";
						failure_reason += std::to_string(p + 1);
						goto failure;
					}
					ctx->SetArgAddress(p, value);
					if (arg_tmods & asTM_OUTREF) out_args.emplace_back(p, value, arg_type_id);
				} else if (!k.GetValue(arg_value, arg_type_id)) {
					// GetValue() fails for a value that isn't a number too (a string or an object for an int parameter), which left val unset and passed whatever it held.
					asINT64 ival;
					double dval;
					if (arg_type_id == asTYPEID_INT32 && k.GetValue(ival)) {
						ctx->SetArgDWord(p, ival);
					} else if (arg_type_id == asTYPEID_FLOAT && k.GetValue(dval)) {
						ctx->SetArgFloat(p, dval);
					} else if (arg_type_id == asTYPEID_BOOL && k.GetValue(ival)) {
						ctx->SetArgByte(p, ival);
					} else {
						failure_reason = "ERROR: Type mismatch for parameter ";
						failure_reason += std::to_string(p + 1);
						goto failure;
					}
				}
				continue;
			}
		}
		// No value for it in args. It gets its default, evaluated as the script compiler would and as async does; an &out parameter without one gets room for its result; a primitive or handle passed by value is left 0 or null, as it always was; anything else is refused, as a reference parameter left a null pointer the function read or wrote through (a crash) and an object passed by value a null object.
		bool has_default;
		has_default = arg_default && std::string_view(arg_default) != "void";
		if (has_default || (arg_tmods & asTM_INOUTREF) == asTM_OUTREF) {
			asITypeInfo* arg_type = g_ScriptEngine->GetTypeInfoById(arg_type_id);
			void* target;
			if (is_value_object) {
				void* obj = g_ScriptEngine->CreateScriptObject(arg_type);
				if (!obj) {
					failure_reason = "ERROR: Can't create a value for parameter ";
					failure_reason += std::to_string(p + 1);
					goto failure;
				}
				if (by_ref) {
					made_objects.emplace_back(obj, arg_type);
					ctx->SetArgAddress(p, obj);
				} else *(void**)ctx->GetAddressOfArg(p) = obj; // The function owns an object passed by value, as if it were a copy made by SetArgObject().
				target = obj;
			} else if (by_ref) {
				target = &ref_values[p];
				if (arg_type_id & asTYPEID_OBJHANDLE) made_handles.emplace_back((void**)target, arg_type);
				ctx->SetArgAddress(p, target);
			} else target = ctx->GetAddressOfArg(p);
			if (arg_tmods & asTM_OUTREF) out_args.emplace_back(p, target, arg_type_id);
			if (!has_default) continue;
			if (!defCtx) defCtx = g_ScriptEngine->RequestContext();
			int dr = defCtx? ExecuteString(g_ScriptEngine, (std::string("return ") + arg_default + ";").c_str(), target, arg_type_id, func->GetModule(), defCtx) : asERROR;
			if (dr != asEXECUTION_FINISHED) {
				failure_reason = "ERROR: Can't evaluate the default value of parameter ";
				failure_reason += std::to_string(p + 1);
				if (dr == asEXECUTION_EXCEPTION) {
					failure_reason += ": ";
					failure_reason += defCtx->GetExceptionString();
				}
				goto failure;
			}
		} else if (by_ref || is_value_object) {
			failure_reason = "ERROR: Missing argument ";
			failure_reason += std::to_string(p + 1);
			goto failure;
		}
	}
	if (defCtx) {
		g_ScriptEngine->ReturnContext(defCtx);
		defCtx = nullptr;
	}
	call_data.current_statement_count = 0;
	call_data.ctx = ctx;
	ctx->SetLineCallback(asFUNCTION(script_function_line_callback), &call_data, asCALL_CDECL);
	int xr;
	{
		script_function_call_scope scope(call_data);
		xr = execute_nested(ctx);
	}
	// The one the context had: the statement counter of the call this one was made in, if any is running on this context, else the one every context has (profiler_callback alone had the debugger stop at no breakpoint after a call).
	if (call_data.outer && call_data.outer->ctx == ctx) ctx->SetLineCallback(asFUNCTION(script_function_line_callback), call_data.outer, asCALL_CDECL);
	else ctx->SetLineCallback(asFUNCTION(nvgt_line_callback), NULL, asCALL_CDECL);
	if (xr != asEXECUTION_FINISHED) {
		if (xr == asEXECUTION_EXCEPTION) {
			char msg[4096];
			const char* section;
			int col;
			const char* decl = ctx->GetExceptionFunction()->GetDeclaration();
			const char* exc = ctx->GetExceptionString();
			int line = ctx->GetExceptionLineNumber(&col, &section);
			snprintf(msg, 4096, "Exception: %s in %s %s at line %d, %d", exc, section, decl, line, col);
			failure_reason = msg;
		} else if (call_data.exceeded) {
			char msg[128];
			snprintf(msg, 128, "maximum statement count of %d exceeded", call_data.max_statement_count);
			failure_reason = msg;
		}
		callstack1 = get_call_stack_ctx(ctx);
		if (ctx != ACtx)
			callstack2 = get_call_stack_ctx(ACtx);
		goto failure;
	}
	// The result: the return value under "0" and the final value of each &out or &inout argument under its own number, which the caller's dictionary holds in place of the arguments it was given. They are gathered before anything is released, as an &out value can be the dictionary's own and a returned reference can point to an argument.
	CScriptDictionary* results;
	results = CScriptDictionary::Create(g_ScriptEngine);
	for (auto& out : out_args) set_call_result(results, std::to_string(std::get<0>(out) + 1), std::get<1>(out), std::get<2>(out));
	asDWORD ret_tmods;
	int ret_type_id;
	ret_type_id = func->GetReturnTypeId(&ret_tmods);
	if (ret_type_id != asTYPEID_VOID) {
		void* ret = ctx->GetAddressOfReturnValue();
		// For a function returning a reference that is where the reference is kept, not the value it refers to, which was read from there: an int & gave the reference's low bits, a string & a string taken from the reference itself.
		if (ret && (ret_tmods & asTM_INOUTREF)) ret = *(void**)ret;
		if (ret) set_call_result(results, "0", ret, ret_type_id);
	}
	if (args) {
		args->DeleteAll();
		*args = *results;
		results->Release();
	} else if (results->GetSize() > 0) args = results;
	else results->Release();
	if (new_context) g_ScriptEngine->ReturnContext(ctx);
	else pop_nested_state(ctx);
	release_made_arguments(made_objects, made_handles);
	g_ScriptEngine->ClearMessageCallback();
	if (errors)
		errors->Release();
	return args;
failure:
	if (errors != NULL && failure_reason != "") {
		errors->InsertLast(&failure_reason);
		errors->InsertLast(&callstack1);
		errors->InsertLast(&callstack2);
	}
	if (ctx) {
		if (new_context) {
			ctx->Unprepare();
			g_ScriptEngine->ReturnContext(ctx);
		} else if (call_data.exceeded) ctx->PopState(); // Our own abort, which ends the called function only
		else pop_nested_state(ctx);
	}
	if (defCtx) g_ScriptEngine->ReturnContext(defCtx);
	release_made_arguments(made_objects, made_handles);
	if (args) {
		args->DeleteAll();
		args->Release();
		args = NULL;
	}
	g_ScriptEngine->ClearMessageCallback();
	if (errors)
		errors->Release();
	return NULL;
}
static bool function_matches_signature(asIScriptFunction* func, asIScriptFunction* sig) {
	asDWORD func_flags, sig_flags;
	if (func->GetObjectType() || func->GetReturnTypeId(&func_flags) != sig->GetReturnTypeId(&sig_flags) || func_flags != sig_flags || func->GetParamCount() != sig->GetParamCount()) return false;
	for (asUINT i = 0; i < func->GetParamCount(); i++) {
		int func_type, sig_type;
		if (func->GetParam(i, &func_type, &func_flags) < 0 || sig->GetParam(i, &sig_type, &sig_flags) < 0 || func_type != sig_type || func_flags != sig_flags) return false;
	}
	return true;
}
bool script_function_retrieve(asIScriptFunction* func, asIScriptFunction** out_func, int type_id) {
	asITypeInfo* ti = g_ScriptEngine->GetTypeInfoById(type_id);
	asIScriptFunction* sig = ti? ti->GetFuncdefSignature() : nullptr;
	if ((type_id & asTYPEID_OBJHANDLE) && sig && function_matches_signature(func, sig)) {
		*out_func = func;
		func->AddRef();
		return true;
	}
	return false;
}
int script_function_get_line(asIScriptFunction* func) {
	const char* section = nullptr;
	int row, col;
	if (!func || func->GetDeclaredAt(&section, &row, &col) < 0) return -1;
	return row;
}
std::string script_function_get_decl(asIScriptFunction* func, bool include_object_name = true, bool include_namespace = true, bool include_param_names = false) {
	if (!func) return "";
	return std::string(func->GetDeclaration(include_object_name, include_namespace, include_param_names));
}
std::string script_function_get_decl_property(asIScriptFunction* func) { return script_function_get_decl(func); }
std::string script_function_get_name(asIScriptFunction* func) {
	if (!func) return "";
	return std::string(func->GetName());
}
std::string script_function_get_namespace(asIScriptFunction* func) {
	if (!func) return "";
	return std::string(func->GetNamespace());
}
std::string script_function_get_declared_at(asIScriptFunction* func, int* row, int* col) {
	const char* script = nullptr;
	if (!func || func->GetDeclaredAt(&script, row, col) < 0) return "";
	return std::string(script);
}
std::string script_function_get_script_property(asIScriptFunction* func) {
	const char* script = nullptr;
	int row, col;
	if (!func || func->GetDeclaredAt(&script, &row, &col) < 0) return "";
	if (!func || func->GetDeclaredAt(&script, &row, &col) < 0) return "";
	return std::string(script);
}
void script_function_line_callback(asIScriptContext* ctx, script_function_call_data* data) {
	nvgt_line_callback(ctx, NULL);
	// AngelScript calls the line callback once more as an execution ends (aborted, suspended, finished), which is no statement. Counted as one, at the limit it marked the call as exceeded when exit() had ended it, and script_function_call took exit()'s abort for its own and dropped it: the script went on, and as the context manager had already let go of its context, a later exit() did nothing. And with the call just finished, its Abort() stayed pending on the script's context and ended the script at its next sleep() or yield().
	if (ctx->GetState() != asEXECUTION_ACTIVE) return;
	// A statement of this call is one of every call it was made in too, so their limits are counted here as well. A limit exceeded by an outer call aborts this one, which passes the abort on to that call (see pop_nested_state), or, in a context of its own, has it end at that call's next statement.
	for (script_function_call_data* d = data; d; d = d->outer) {
		if (d->max_statement_count < 1) continue;
		d->current_statement_count += 1;
		if (d->current_statement_count > d->max_statement_count) {
			d->exceeded = true;
			ctx->Abort();
			return;
		}
	}
}
class script_module_bytecode_stream : public asIBinaryStream {
	std::string data;
	int cursor;
public:
	script_module_bytecode_stream(const std::string& code = "") : data(code), cursor(0) {}
	void set(const std::string& code) {
		data = code;
		cursor = 0;
	}
	std::string get() {
		return data;
	}
	int Write(const void* ptr, asUINT size) {
		data.append((char*)ptr, size);
		return size;
	}
	int Read(void* ptr, asUINT size) {
		if (cursor >= data.size()) return -1;
		asUINT available = static_cast<asUINT>(data.size() - cursor);
		asUINT to_copy = size < available ? size : available;
		memcpy(ptr, data.data() + cursor, to_copy);
		cursor += to_copy;
		return to_copy;
	}
};
class script_module {
	std::string mod_name;
	asIScriptModule* get_mod() { return g_ScriptEngine->GetModule(mod_name.c_str(), asGM_ONLY_IF_EXISTS); }
	int RefCount;
	bool exists;
public:
	unsigned int max_statement_count;
	script_module(asIScriptModule* module, bool e) {
		mod_name = module->GetName();
		exists = e;
		RefCount = 1;
		max_statement_count = 0;
	}
	void AddRef() {
		asAtomicInc(RefCount);
	}
	void Release() {
		if (asAtomicDec(RefCount) < 1)
			delete this;
	}
	int add_section(const std::string& name, const std::string& code, int line_offset = 0) {
		if (!get_mod())
			return asNO_MODULE;
		return get_mod()->AddScriptSection(name.c_str(), code.c_str(), code.size(), line_offset);
	}
	int build(CScriptArray* errors) {
		if (!get_mod())
			return asNO_MODULE;
		g_ScriptEngine->SetMessageCallback(asFUNCTION(script_message_callback), errors, asCALL_CDECL);
		int result = get_mod()->Build();
		g_ScriptEngine->ClearMessageCallback();
		if (errors)
			errors->Release();
		return result;
	}
	std::string get_bytecode(bool release) {
		if (!get_mod()) return "";
		script_module_bytecode_stream b;
		if (get_mod()->SaveByteCode(&b, release) < 0) return "";
		return b.get();
	}
	int set_bytecode(const std::string& code, bool* release = NULL, CScriptArray* errors = NULL) {
		if (!get_mod()) {
			if (errors)
				errors->Release();
			return asNO_MODULE;
		}
		g_ScriptEngine->SetMessageCallback(asFUNCTION(script_message_callback), errors, asCALL_CDECL);
		script_module_bytecode_stream b(code);
		int ret = get_mod()->LoadByteCode(&b, release);
		g_ScriptEngine->ClearMessageCallback();
		if (errors)
			errors->Release();
		return ret;
	}
	int reset_globals(CScriptArray* errors) {
		if (!get_mod()) {
			if (errors)
				errors->Release();
			return asNO_MODULE;
		}
		g_ScriptEngine->SetMessageCallback(asFUNCTION(script_message_callback), errors, asCALL_CDECL);
		asIScriptContext* ctx = g_ScriptEngine->RequestContext();
		if (!ctx) {
			std::string err = "ERROR: failed to acquire context";
			if (errors)
				errors->InsertLast(&err);
			g_ScriptEngine->ClearMessageCallback();
			if (errors)
				errors->Release();
			return asERROR;
		}
		int result = get_mod()->ResetGlobalVars(ctx);
		g_ScriptEngine->ClearMessageCallback();
		if (ctx) {
			ctx->Unprepare();
			g_ScriptEngine->ReturnContext(ctx);
		}
		if (errors)
			errors->Release();
		return result;
	}
	int bind_all_imported_functions() {
		if (!get_mod())
			return asNO_MODULE;
		return get_mod()->BindAllImportedFunctions();
	}
	int bind_imported_function(asUINT index, asIScriptFunction* func) {
		if (!get_mod())
			return asNO_MODULE;
		if (!func)
			return asNO_FUNCTION;
		return get_mod()->BindImportedFunction(index, func);
	}
	asIScriptFunction* compile_function(const std::string& section_name, const std::string& code, CScriptArray* errors, bool add_to_module = false, asDWORD line_offset = 0) {
		if (!get_mod()) {
			if (errors) errors->Release();
			return NULL;
		}
		g_ScriptEngine->SetMessageCallback(asFUNCTION(script_message_callback), errors, asCALL_CDECL);
		asIScriptFunction* out_ptr;
		int result = get_mod()->CompileFunction(section_name.c_str(), code.c_str(), line_offset, (add_to_module ? asCOMP_ADD_TO_MODULE : 0), &out_ptr);
		g_ScriptEngine->ClearMessageCallback();
		if (result < 0) {
			if (errors) errors->Release();
			return NULL;
		}
		if (errors) errors->Release();
		return out_ptr;
	}
	int compile_global(const std::string& section_name, const std::string& code, CScriptArray* errors, asDWORD line_offset = 0) {
		if (!get_mod()) {
			if (errors) errors->Release();
			return asNO_MODULE;
		}
		g_ScriptEngine->SetMessageCallback(asFUNCTION(script_message_callback), errors, asCALL_CDECL);
		int result = get_mod()->CompileGlobalVar(section_name.c_str(), code.c_str(), line_offset);
		g_ScriptEngine->ClearMessageCallback();
		if (errors) errors->Release();
		return result;
	}
	void discard() {
		if (!get_mod()) return;
		get_mod()->Discard();
	}
	asDWORD get_function_count() {
		if (!get_mod()) return 0;
		return get_mod()->GetFunctionCount();
	}
	asDWORD get_global_count() {
		if (!get_mod()) return 0;
		return get_mod()->GetGlobalVarCount();
	}
	asDWORD get_imported_function_count() {
		if (!get_mod()) return 0;
		return get_mod()->GetImportedFunctionCount();
	}
	asDWORD set_access_mask(asDWORD mask) {
		if (!get_mod()) return 0;
		return get_mod()->SetAccessMask(mask);
	}
	asIScriptFunction* get_function_by_index(int index) {
		if (!get_mod()) return NULL;
		return get_mod()->GetFunctionByIndex(index);
	}
	asIScriptFunction* get_function_by_name(const std::string& name) {
		if (!get_mod()) return NULL;
		return get_mod()->GetFunctionByName(name.c_str());
	}
	asIScriptFunction* get_function_by_decl(const std::string& name) {
		if (!get_mod()) return NULL;
		return get_mod()->GetFunctionByDecl(name.c_str());
	}
	const std::string get_imported_function_decl(asDWORD index) {
		if (!get_mod())
			return "";
		const char* result = get_mod()->GetImportedFunctionDeclaration(index);
		if (!result) return "";
		return std::string(result);
	}
	int get_imported_function_index(const std::string& decl) {
		if (!get_mod())
			return asNO_MODULE;
		return get_mod()->GetImportedFunctionIndexByDecl(decl.c_str());
	}
	const std::string get_imported_function_module(asDWORD index) {
		if (!get_mod())
			return "";
		const char* result = get_mod()->GetImportedFunctionSourceModule(index);
		if (!result) return "";
		return std::string(result);
	}
	CScriptAny* get_global(asDWORD index) {
		if (!get_mod())
			return NULL;
		const char* name;
		int type_id;
		if (get_mod()->GetGlobalVar(index, &name, NULL, &type_id) < 0)
			return NULL;
		void* ref = get_mod()->GetAddressOfGlobalVar(index);
		if (!ref) return NULL;
		return new CScriptAny(ref, type_id, g_ScriptEngine);
	}
	const std::string get_global_decl(asDWORD index) {
		if (!get_mod())
			return "";
		const char* result = get_mod()->GetGlobalVarDeclaration(index);
		if (!result) return "";
		return std::string(result);
	}
	int get_global_index_by_decl(const std::string& decl) {
		if (!get_mod())
			return asNO_MODULE;
		return get_mod()->GetGlobalVarIndexByDecl(decl.c_str());
	}
	int get_global_index_by_name(const std::string& decl) {
		if (!get_mod())
			return asNO_MODULE;
		return get_mod()->GetGlobalVarIndexByName(decl.c_str());
	}
	const std::string get_global_name(asDWORD index) {
		if (!get_mod())
			return "";
		const char* result;
		if (get_mod()->GetGlobalVar(index, &result) < 0) return "";
		if (!result) return "";
		return std::string(result);
	}
	const std::string get_name() {
		if (!get_mod())
			return "";
		const char* result = get_mod()->GetName();
		if (!result) return "";
		return std::string(result);
	}
	void set_name(const std::string& name) {
		if (!get_mod()) return;
		get_mod()->SetName(name.c_str());
		mod_name = name;
	}
};
script_module* script_get_module(const std::string& name, int mode) {
	bool exists = false;
	if (mode != asGM_ALWAYS_CREATE) exists = g_ScriptEngine->GetModule(name.c_str(), asGM_ONLY_IF_EXISTS) != NULL;
	asIScriptModule* mod = g_ScriptEngine->GetModule(name.c_str(), (asEGMFlags)mode);
	if (!mod) return NULL;
	return new script_module(mod, exists);
}
void RegisterScripting(asIScriptEngine* engine) {
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_SCRIPTING);
	engine->RegisterObjectType(_O("script_function"), 0, asOBJ_REF);
	engine->RegisterObjectBehaviour(_O("script_function"), asBEHAVE_ADDREF, _O("void f()"), asMETHOD(asIScriptFunction, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("script_function"), asBEHAVE_RELEASE, _O("void f()"), asMETHOD(asIScriptFunction, Release), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_function"), _O("dictionary@ call(dictionary@ args, string[]@ errors = null, int max_statement_count = 0)"), asFUNCTION(script_function_call), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("dictionary@ opCall(dictionary@ args, string[]@ errors = null, int max_statement_count = 0)"), asFUNCTION(script_function_call), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool retrieve(?&out)"), asFUNCTION(script_function_retrieve), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("string get_declared_at(int& row, int& column)"), asFUNCTION(script_function_get_declared_at), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("string get_decl(bool include_object_name, bool include_namespace = true, bool include_param_names = true)"), asFUNCTION(script_function_get_decl), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("string get_decl() property"), asFUNCTION(script_function_get_decl_property), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("string get_name() property"), asFUNCTION(script_function_get_name), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("string get_namespace() property"), asFUNCTION(script_function_get_namespace), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("string get_script() property"), asFUNCTION(script_function_get_script_property), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("int get_line() property"), asFUNCTION(script_function_get_line), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool get_is_explicit() property"), asMETHOD(asIScriptFunction, IsExplicit), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool get_is_final() property"), asMETHOD(asIScriptFunction, IsFinal), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool get_is_override() property"), asMETHOD(asIScriptFunction, IsOverride), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool get_is_private() property"), asMETHOD(asIScriptFunction, IsPrivate), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool get_is_property() property"), asMETHOD(asIScriptFunction, IsProperty), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool get_is_protected() property"), asMETHOD(asIScriptFunction, IsProtected), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool get_is_read_only() property"), asMETHOD(asIScriptFunction, IsReadOnly), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_function"), _O("bool get_is_shared() property"), asMETHOD(asIScriptFunction, IsShared), asCALL_THISCALL);
	engine->RegisterObjectType(_O("script_module"), 0, asOBJ_REF);
	engine->RegisterObjectBehaviour(_O("script_module"), asBEHAVE_ADDREF, _O("void f()"), asMETHOD(script_module, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("script_module"), asBEHAVE_RELEASE, _O("void f()"), asMETHOD(script_module, Release), asCALL_THISCALL);
	engine->RegisterObjectProperty(_O("script_module"), _O("uint max_statement_count"), asOFFSET(script_module, max_statement_count));
	engine->RegisterObjectMethod(_O("script_module"), _O("int add_section(const string&in name, const string&in code, uint line_offset=0)"), asMETHOD(script_module, add_section), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int build(string[]@ errors=null)"), asMETHOD(script_module, build), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("string get_bytecode(bool strip_debug_info)"), asMETHOD(script_module, get_bytecode), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int set_bytecode(const string&in code, bool&out debug_info_was_stripped, string[]@ errors=null)"), asMETHOD(script_module, set_bytecode), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int reset_globals(string[]@ errors=null)"), asMETHOD(script_module, reset_globals), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int bind_all_imported_functions()"), asMETHOD(script_module, bind_all_imported_functions), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int bind_imported_function(uint index, script_function@+ func)"), asMETHOD(script_module, bind_imported_function), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int compile_global(const string&in section_name, const string&in code, uint line_offset=0)"), asMETHOD(script_module, compile_global), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("script_function@ compile_function(const string&in section_name, const string&in code, string[]@ errors=null, bool add_to_module=false, uint line_offset=0)"), asMETHOD(script_module, compile_function), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("void discard()"), asMETHOD(script_module, discard), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("script_function@+ get_function_by_decl(const string&in decl)"), asMETHOD(script_module, get_function_by_decl), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("script_function@+ get_function_by_index(uint index)"), asMETHOD(script_module, get_function_by_index), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("script_function@+ get_function_by_name(const string&in name)"), asMETHOD(script_module, get_function_by_name), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("any@ get_global(uint index)"), asMETHOD(script_module, get_global), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("const string get_global_decl(uint index)"), asMETHOD(script_module, get_global_decl), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int get_global_index_by_decl(const string&in decl)"), asMETHOD(script_module, get_global_index_by_decl), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int get_global_index_by_name(const string&in name)"), asMETHOD(script_module, get_global_index_by_name), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("const string get_global_name(uint index)"), asMETHOD(script_module, get_global_name), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("uint get_function_count()"), asMETHOD(script_module, get_function_count), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("uint get_global_count()"), asMETHOD(script_module, get_global_count), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("uint get_imported_function_count()"), asMETHOD(script_module, get_imported_function_count), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("uint set_access_mask(uint mask)"), asMETHOD(script_module, set_access_mask), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("const string get_imported_function_decl(uint index)"), asMETHOD(script_module, get_imported_function_decl), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("int get_imported_function_index(const string&in decl)"), asMETHOD(script_module, get_imported_function_index), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("const string get_imported_function_module(uint index)"), asMETHOD(script_module, get_imported_function_module), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("string get_name() property"), asMETHOD(script_module, get_name), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("script_module"), _O("void set_name(const string&in name) property"), asMETHOD(script_module, set_name), asCALL_THISCALL);
	engine->RegisterGlobalFunction(_O("script_module@ script_get_module(const string&in name, int mode=1)"), asFUNCTION(script_get_module), asCALL_CDECL);
}
void RegisterScriptstuff(asIScriptEngine* engine) {
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_UNCLASSIFIED);
	engine->RegisterGlobalProperty("const bool profiler_is_running", &is_profiling);
	engine->RegisterGlobalFunction("int get_garbage_collect_mode() property", asFUNCTION(get_garbage_collect_mode), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_garbage_collect_mode(int mode) property", asFUNCTION(set_garbage_collect_mode), asCALL_CDECL);
	engine->RegisterGlobalFunction("int get_garbage_collect_auto_frequency() property", asFUNCTION(get_garbage_collect_auto_frequency), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_garbage_collect_auto_frequency(int frequency) property", asFUNCTION(set_garbage_collect_auto_frequency), asCALL_CDECL);
	engine->RegisterGlobalFunction("void garbage_collect(bool full = true)", asFUNCTION(garbage_collect), asCALL_CDECL);
	engine->RegisterGlobalFunction("void start_profiling()", asFUNCTION(start_profiling), asCALL_CDECL);
	engine->RegisterGlobalFunction("void stop_profiling()", asFUNCTION(stop_profiling), asCALL_CDECL);
	engine->RegisterGlobalFunction("void reset_profiler()", asFUNCTION(reset_profiler), asCALL_CDECL);
	engine->RegisterGlobalFunction("string generate_profile(bool reset = true)", asFUNCTION(generate_profile), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_GENERAL);
	engine->RegisterGlobalFunction("string get_call_stack() property", asFUNCTION(get_call_stack), asCALL_CDECL);
	engine->RegisterGlobalFunction("int get_call_stack_size() property", asFUNCTION(get_call_stack_size), asCALL_CDECL);
	engine->RegisterGlobalFunction("string get_SCRIPT_CURRENT_FUNCTION() property", asFUNCTION(get_script_current_function), asCALL_CDECL);
	engine->RegisterGlobalFunction("string get_SCRIPT_CURRENT_FILE() property", asFUNCTION(get_script_current_file), asCALL_CDECL);
	engine->RegisterGlobalFunction("int get_SCRIPT_CURRENT_LINE() property", asFUNCTION(get_script_current_line), asCALL_CDECL);
	engine->RegisterGlobalFunction("string get_SCRIPT_MAIN_PATH() property", asFUNCTION(get_script_path), asCALL_CDECL);
	engine->RegisterGlobalFunction("void assert(bool expression, const string&in fail_text = \"\")", asFUNCTION(script_assert), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_UNCLASSIFIED);
	engine->RegisterGlobalFunction("string get_SCRIPT_EXECUTABLE() property", asFUNCTION(get_script_executable), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_SCRIPT_COMPILED() property", asFUNCTION(script_compiled), asCALL_CDECL);
	engine->RegisterGlobalFunction("string get_function_signature(?&in)", asFUNCTION(get_function_signature), asCALL_CDECL);
	engine->RegisterGlobalFunction("void acquire_exclusive_lock()", asFUNCTION(asAcquireExclusiveLock), asCALL_CDECL);
	engine->RegisterGlobalFunction("void release_exclusive_lock()", asFUNCTION(asReleaseExclusiveLock), asCALL_CDECL);
	engine->RegisterGlobalFunction("void acquire_shared_lock()", asFUNCTION(asAcquireSharedLock), asCALL_CDECL);
	engine->RegisterGlobalFunction("void release_shared_lock()", asFUNCTION(asReleaseSharedLock), asCALL_CDECL);
	engine->RegisterGlobalFunction("void script_dump_engine_configuration(datastream@+ output)", asFUNCTION(dump_angelscript_engine_configuration), asCALL_CDECL);
	RegisterScripting(engine);
}
