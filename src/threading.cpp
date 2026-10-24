/* threading.cpp - code for wrapping threads and multithreading primatives (usually from Poco)
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

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>
#include <Poco/Event.h>
#include <Poco/Format.h>
#include <Poco/Mutex.h>
#include <Poco/NamedMutex.h>
#include <Poco/RefCountedObject.h>
#include <Poco/Runnable.h>
#include <Poco/RWLock.h>
#include <Poco/ScopedLock.h>
#include <Poco/Thread.h>
#include <Poco/ThreadPool.h>
#include <angelscript.h>
#include <scriptdictionary.h>
#include <scripthelper.h>
#include <obfuscate.h>
#include "nvgt.h"
#include "pocostuff.h"
#include "scriptstuff.h"
#include "threading.h"
#ifdef __ANDROID__
	#include <unistd.h> // gettid
#endif
using namespace Poco;

// A number, bool or enum given to async for a parameter of another of those types, converted by its value. It was passed by its size: an int for a float parameter arrived as the bits of the int (5 as 7e-45), an int64 for a double and a float for an int likewise, and a value of another size was refused. A number converts as a direct call converts it, a bool to 1 or 0, and to a bool any value but 0 is true; an enum is read and written as its underlying type (enum E : int8 is one byte). Returns false for a type that isn't one of these.
static asINT64 real_to_int64(double d) {
	if (d != d) return 0;
	if (d >= 9223372036854775807.0) return INT64_MAX;
	if (d <= -9223372036854775808.0) return INT64_MIN;
	return asINT64(d);
}
static int enum_underlying_type(asIScriptEngine* engine, int type) {
	if (type <= asTYPEID_DOUBLE || (type & asTYPEID_MASK_OBJECT)) return type;
	asITypeInfo* ti = engine->GetTypeInfoById(type);
	return ti ? ti->GetUnderlyingTypeId() : asTYPEID_INT32;
}
static bool convert_number(asIScriptEngine* engine, int from_type, const void* from, int to_type, void* to) {
	from_type = enum_underlying_type(engine, from_type);
	to_type = enum_underlying_type(engine, to_type);
	asINT64 i = 0;
	double d = 0;
	bool real = false;
	switch (from_type) {
		case asTYPEID_BOOL: i = *(const asBYTE*)from ? 1 : 0; break;
		case asTYPEID_INT8: i = *(const asINT8*)from; break;
		case asTYPEID_INT16: i = *(const asINT16*)from; break;
		case asTYPEID_INT32: i = *(const int*)from; break;
		case asTYPEID_INT64: i = *(const asINT64*)from; break;
		case asTYPEID_UINT8: i = *(const asBYTE*)from; break;
		case asTYPEID_UINT16: i = *(const asWORD*)from; break;
		case asTYPEID_UINT32: i = *(const asDWORD*)from; break;
		case asTYPEID_UINT64: i = asINT64(*(const asQWORD*)from); break;
		case asTYPEID_FLOAT: d = *(const float*)from; real = true; break;
		case asTYPEID_DOUBLE: d = *(const double*)from; real = true; break;
		default: return false;
	}
	if (to_type == asTYPEID_BOOL) {
		*(asBYTE*)to = (real ? d != 0 : i != 0) ? 1 : 0;
		return true;
	}
	// A uint64 holds the reals from 2^63 up to 2^64, beyond an int64: they were clamped to 2^63 - 1 (1e19 arrived as 9223372036854775807, while a direct call passes 10000000000000000000).
	if (real && to_type == asTYPEID_UINT64 && d >= 9223372036854775808.0) i = asINT64(d < 18446744073709551616.0 ? asQWORD(d) : ~asQWORD(0));
	else if (real && to_type != asTYPEID_FLOAT && to_type != asTYPEID_DOUBLE) i = real_to_int64(d);
	switch (to_type) {
		case asTYPEID_INT8: *(asINT8*)to = asINT8(i); break;
		case asTYPEID_INT16: *(asINT16*)to = asINT16(i); break;
		case asTYPEID_INT32: *(int*)to = int(i); break;
		case asTYPEID_INT64: *(asINT64*)to = i; break;
		case asTYPEID_UINT8: *(asBYTE*)to = asBYTE(i); break;
		case asTYPEID_UINT16: *(asWORD*)to = asWORD(i); break;
		case asTYPEID_UINT32: *(asDWORD*)to = asDWORD(i); break;
		case asTYPEID_UINT64: *(asQWORD*)to = asQWORD(i); break;
		case asTYPEID_FLOAT: *(float*)to = real ? float(d) : from_type == asTYPEID_UINT64 ? float(asQWORD(i)) : float(i); break;
		case asTYPEID_DOUBLE: *(double*)to = real ? d : from_type == asTYPEID_UINT64 ? double(asQWORD(i)) : double(i); break;
		default: return false;
	}
	return true;
}

// Raises the failure to set up an async call's argument on the calling context, unless setting it up raised an exception of its own there:
// a script class's constructor, copy constructor or opAssign (making the object, or assigning a default value to it) runs as a nested
// call on that context, and AngelScript forwards its exception to it with its own text and line, which say why (this text, raised over
// it, said only which argument).
static void async_arg_failed(asIScriptContext* aCtx, const std::string& text) {
	if (aCtx->GetState() != asEXECUTION_EXCEPTION)
		aCtx->SetException(text.c_str());
}

// We'll put the code for the highest level of nvgt's multithreading support on the top this time. This allows an nvgt user to write a line of code such as async<string> result(url_get, "https://nvgt.dev"); and after result.try_wait(ms) returns true, user can fetch result with result.value or opImplCast.
class async_result : public RefCountedObject, public Runnable {
	void* value;
	asITypeInfo* subtype;
	int subtypeid;
	Thread* task; // A pointer instead of a direct object because if an async_result object is created from a thread pool or has not yet been set up, a specific thread will not exist for it.
	asIScriptContext* ctx; // The angelscript context used to call the function asynchronously, stored as a property because we need to pass it between functions in this class without arguments.
	std::vector<std::pair<void*, asITypeInfo*>> value_args; // Value typed arguments must be copied before being passed to the destination function on another thread, this is because such arguments reside on the stack and so they would otherwise get destroyed when the async_result::call method unwinds but well before the destination function returns. Store pointers to such copied arguments here so they can be released later. Objects made for reference parameters (a default value) and objects passed by handle to a reference parameter, which the caller can let go of before the function runs, are held here too (a list, as the same object can be passed twice).
	std::vector<asQWORD> ref_values; // The values whose addresses reference parameters of primitive or handle types are given (8 bytes hold any primitive or a handle), sized once in call() so that the addresses stay valid until the function has run.
	std::vector<std::pair<void**, asITypeInfo*>> ref_handles; // The handles held in ref_values, released (whatever the function left there) once the call is over.
	std::string exception; // Set to an exception string if an exception is thrown from within the async function call.
	bool returns_reference; // The function returns a reference (int& f()), whose value run() reads through it.
	// The function finished and its result was taken. An empty exception string was the only sign of success, so an execution that ended in an exception whose message is empty (throw("")), or a result whose copy failed, read as a success: failed was false and the value was read from a null pointer.
	bool succeeded;
public:
	Event progress; // Public so that some functions in this object can be called directly from Angelscript such as wait and tryWait.
	async_result(asITypeInfo* t) : value(nullptr), subtype(t), subtypeid(subtype->GetSubTypeId()), progress(Event::EVENT_MANUALRESET), task(nullptr), ctx(nullptr), returns_reference(false), succeeded(false) {}
	~async_result() {
		if (task) angelscript_refcounted_release<Thread>(task);
		release_value_args();
		if (value) {
			if (subtypeid & asTYPEID_MASK_OBJECT) subtype->GetEngine()->ReleaseScriptObject(*(void**)value, subtype->GetSubType());
			free(value);
		}
	}
	void* get_value() {
		if (!ctx) throw NullValueException("Object not initialized");
		progress.wait();
		if (!succeeded) throw Exception(exception);
		if ((subtypeid & asTYPEID_MASK_OBJECT) && !(subtypeid & asTYPEID_OBJHANDLE))
			return *(void**)value;
		else return value;
	}
	std::string get_exception() { return progress.tryWait(0) ? exception : ""; }
	void wait() {
		if (!ctx) throw NullValueException("Object not initialized");
		progress.wait();
	}
	bool call(asIScriptGeneric* gen, ThreadPool* pool = nullptr) {
		asIScriptContext* aCtx = asGetActiveContext();
		asIScriptEngine* engine = aCtx->GetEngine();
		asIScriptFunction* func;
		int func_typeid = gen->GetArgTypeId(1);
		asITypeInfo* func_type = engine->GetTypeInfoById(func_typeid);
		if (!func_type || !(func_type->GetFlags() & asOBJ_FUNCDEF)) {
			aCtx->SetException("First argument to async must be a callable function");
			return false;
		}
		if (func_typeid & asTYPEID_OBJHANDLE) func = *(asIScriptFunction**)gen->GetArgAddress(1);
		else func = (asIScriptFunction*)gen->GetArgAddress(1);
		if (!func) {
			aCtx->SetException("Cannot call a null function asynchronously");
			return false;
		}
		asDWORD return_flags = 0;
		if (func->GetReturnTypeId(&return_flags) != subtypeid) {
			aCtx->SetException(format("return type of %s is incompatible with async result type %s", std::string(func->GetDeclaration()), std::string(engine->GetTypeDeclaration(subtypeid))).c_str());
			return false;
		}
		returns_reference = (return_flags & asTM_INOUTREF) != 0;
		ctx = engine->RequestContext();
		if (!ctx || ctx->Prepare(func) < 0) {
			aCtx->SetException("Async can't prepare calling context");
			engine->ReturnContext(ctx);
			return false;
		}
		ref_values.assign(func->GetParamCount(), 0);
		asIScriptFunction* decl_func = get_default_args_function(func); // A delegate's default arguments are its method's, see there.
		asIScriptContext* defCtx = nullptr; // We may need an extra context if we are required to evaluate expressions for default arguments.
		for (unsigned int i = 0; i < func->GetParamCount(); i++) {
			// In this context, param will be the argument as being received by the calling function and arg will be the argument as being passed to this async::call function.
			int param_typeid, arg_typeid;
			asITypeInfo* param_type, * arg_type;
			asDWORD param_flags, arg_flags;
			const char* param_default;
			int success = decl_func->GetParam(i, &param_typeid, &param_flags, nullptr, &param_default);
			if (success < 0) {
				aCtx->SetException(format("Angelscript error %d while setting art %u of async call to %s", success, i, std::string(func->GetDeclaration())).c_str());
				engine->ReturnContext(ctx);
				return false;
			}
			// A reference parameter takes the address of its value. A default value or a handle was written in its place, so the function took the value for an address (a crash for a const int &in = 5) or an object's address for a handle's, and an object made for a default value was never released.
			bool by_ref = (param_flags & asTM_INOUTREF) != 0;
			bool param_is_handle = (param_typeid & asTYPEID_OBJHANDLE) != 0;
			if (gen->GetArgCount() - 2 <= i) {
				if (!param_default) {
					aCtx->SetException("Not enough arguments");
					engine->ReturnContext(ctx);
					return false;
				}
				// We must initialize the default arguments ourselves.
				if (!defCtx) defCtx = engine->RequestContext();
				if (!defCtx) {
					aCtx->SetException("Cannot attain context to evaluate default async call argument expressions");
					engine->ReturnContext(ctx);
					return false;
				}
				param_type = engine->GetTypeInfoById(param_typeid);
				bool param_is_value_object = param_typeid & asTYPEID_MASK_OBJECT && !(param_typeid & asTYPEID_OBJHANDLE);
				void* default_ref;
				if (param_is_value_object) {
					// Create a copy of the object.
					void* obj = engine->CreateScriptObject(param_type);
					if (!obj) {
						async_arg_failed(aCtx, format("Cannot create empty object for default assign of argument %u of async function call", i + 1));
						engine->ReturnContext(ctx);
						engine->ReturnContext(defCtx);
						return false;
					}
					if (by_ref) {
						value_args.emplace_back(obj, param_type); // The function only refers to it.
						ctx->SetArgAddress(i, obj);
					} else *(void**)ctx->GetAddressOfArg(i) = obj; // The function owns an object passed by value.
					default_ref = obj;
				} else if (by_ref) {
					default_ref = &ref_values[i];
					if (param_is_handle) ref_handles.emplace_back((void**)default_ref, param_type);
					ctx->SetArgAddress(i, default_ref);
				} else default_ref = ctx->GetAddressOfArg(i);
				// An &out parameter declared = void gets the room made above for its result (null was passed, which the function wrote through, and SetArgObject() refused a primitive one).
				if (std::string_view(param_default) == "void") success = asEXECUTION_FINISHED;
				else success = ExecuteString(engine, format("return %s;", std::string(param_default)).c_str(), default_ref, param_typeid, decl_func->GetModule(), defCtx, decl_func->GetNamespace()); // In the function's namespace, as the compiler evaluates it.
				// Not only a negative error: ExecuteString returns the result of the execution, and one ending in an exception (or an abort) gave no value, so the call went ahead with the argument left unset.
				if (success != asEXECUTION_FINISHED) {
					std::string why = success == asEXECUTION_EXCEPTION? ": " + std::string(defCtx->GetExceptionString()) : "";
					async_arg_failed(aCtx, format("Angelscript error %d while setting default argument %u in async call to %s%s", success, i + 1, std::string(func->GetDeclaration()), why));
					engine->ReturnContext(ctx);
					engine->ReturnContext(defCtx);
					return false;
				}
				continue;
			}
			arg_typeid = gen->GetArgTypeId(i + 2);
			arg_type = engine->GetTypeInfoById(arg_typeid);
			param_type = engine->GetTypeInfoById(param_typeid);
			success = asINVALID_ARG;
			if (arg_typeid == asTYPEID_VOID) {
				if (by_ref && param_is_handle) {
					// A null handle, held here like any other, as the function may store one there.
					ref_handles.emplace_back((void**)&ref_values[i], param_type);
					success = ctx->SetArgAddress(i, &ref_values[i]);
				} else if (by_ref) success = asINVALID_TYPE; // There is no value to refer to, and the function read or wrote through address 0.
				else success = ctx->SetArgAddress(i, nullptr);
			}
			else if (arg_typeid & asTYPEID_MASK_OBJECT && !(arg_type && param_type && (arg_type == param_type || arg_type->DerivesFrom(param_type) || arg_type->Implements(param_type)))) success = asINVALID_TYPE;
			else if (!(arg_typeid & asTYPEID_MASK_OBJECT) && by_ref) {
				// A number for a reference parameter: the function refers to a copy of it here, as it would to a temporary in a direct call, converted if it is of another type (see convert_number()). SetArgDWord() and the rest refused it, as they take no reference.
				if (arg_typeid == param_typeid) {
					memcpy(&ref_values[i], gen->GetArgAddress(i + 2), engine->GetSizeOfPrimitiveType(arg_typeid));
					success = ctx->SetArgAddress(i, &ref_values[i]);
				} else if (!(param_typeid & asTYPEID_MASK_OBJECT) && convert_number(engine, arg_typeid, gen->GetArgAddress(i + 2), param_typeid, &ref_values[i])) success = ctx->SetArgAddress(i, &ref_values[i]);
				else success = asINVALID_TYPE;
			} else if (!(arg_typeid & asTYPEID_MASK_OBJECT) && !(param_typeid & asTYPEID_MASK_OBJECT) && arg_typeid != param_typeid) {
				// A number, bool or enum for a parameter of another of those types, see convert_number().
				void* slot = ctx->GetAddressOfArg(i);
				success = slot && convert_number(engine, arg_typeid, gen->GetArgAddress(i + 2), param_typeid, slot)? asSUCCESS : asINVALID_TYPE;
			} else if (!(arg_typeid & asTYPEID_MASK_OBJECT) && arg_typeid > asTYPEID_DOUBLE) {
				// An enum value, passed by its size; it matched none of the types below and was refused.
				asUINT size = engine->GetSizeOfPrimitiveType(arg_typeid);
				void* value = gen->GetArgAddress(i + 2);
				if (size == 1) success = ctx->SetArgByte(i, *(asBYTE*)value);
				else if (size == 2) success = ctx->SetArgWord(i, *(asWORD*)value);
				else if (size == 8) success = ctx->SetArgQWord(i, *(asQWORD*)value);
				else success = ctx->SetArgDWord(i, *(asDWORD*)value);
			}
			else if (arg_typeid == asTYPEID_BOOL || arg_typeid == asTYPEID_INT8 || arg_typeid == asTYPEID_UINT8) success = ctx->SetArgByte(i, *(asBYTE*)gen->GetArgAddress(i + 2));
			else if (arg_typeid == asTYPEID_INT16 || arg_typeid == asTYPEID_UINT16) success = ctx->SetArgWord(i, *(asWORD*)gen->GetArgAddress(i + 2));
			else if (arg_typeid == asTYPEID_INT32 || arg_typeid == asTYPEID_UINT32) success = ctx->SetArgDWord(i, *(asDWORD*)gen->GetArgAddress(i + 2));
			else if (arg_typeid == asTYPEID_INT64 || arg_typeid == asTYPEID_UINT64) success = ctx->SetArgQWord(i, *(asQWORD*)gen->GetArgAddress(i + 2));
			else if (arg_typeid == asTYPEID_FLOAT) success = ctx->SetArgFloat(i, *(float*)gen->GetArgAddress(i + 2));
			else if (arg_typeid == asTYPEID_DOUBLE) success = ctx->SetArgDouble(i, *(double*)gen->GetArgAddress(i + 2));
			else if (arg_typeid & asTYPEID_MASK_OBJECT && arg_typeid & asTYPEID_OBJHANDLE) {
				void* obj = *(void**)gen->GetArgAddress(i + 2);
				if (by_ref && param_is_handle) {
					// A reference to a handle takes the address of a handle, held here.
					*(void**)&ref_values[i] = obj;
					if (obj) engine->AddRefScriptObject(obj, arg_type);
					ref_handles.emplace_back((void**)&ref_values[i], param_type);
					success = ctx->SetArgAddress(i, &ref_values[i]);
				} else if (!obj && !param_is_handle) success = asINVALID_TYPE; // A null handle for an object, refused like null itself (above): the function got a null reference or object.
				else {
					success = ctx->SetArgObject(i, obj);
					// An object passed by value is copied by SetArgObject(), which leaves the argument null when the copy fails (the copy constructor of a script class raised an exception): the function ran with a null object.
					if (success >= 0 && !by_ref && !param_is_handle && !*(void**)ctx->GetAddressOfArg(i)) {
						async_arg_failed(aCtx, format("Cannot copy object for argument %u of async function call", i + 1));
						engine->ReturnContext(ctx);
						return false;
					}
					// A reference to the object: the caller's handle can be let go of before the function runs on its thread, so the object is held until the call is over.
					if (success >= 0 && by_ref && obj) {
						engine->AddRefScriptObject(obj, arg_type);
						value_args.emplace_back(obj, arg_type);
					}
				}
			} else if (arg_typeid & asTYPEID_MASK_OBJECT) {
				void* obj = engine->CreateScriptObjectCopy(gen->GetArgAddress(i + 2), arg_type);
				if (!obj) {
					async_arg_failed(aCtx, format("Cannot copy object for argument %u of async function call", i + 1));
					engine->ReturnContext(ctx);
					return false;
				}
				if (by_ref && param_is_handle) {
					// The copy's reference is the handle the function refers to, which it may replace.
					*(void**)&ref_values[i] = obj;
					ref_handles.emplace_back((void**)&ref_values[i], param_type);
					success = ctx->SetArgAddress(i, &ref_values[i]);
				} else {
					success = ctx->SetArgObject(i, obj);
					if (success >= 0) value_args.emplace_back(obj, arg_type);
					else engine->ReleaseScriptObject(obj, arg_type);
					// By value, the function gets a copy SetArgObject() makes of the copy, null if that fails (see above).
					if (success >= 0 && !by_ref && !*(void**)ctx->GetAddressOfArg(i)) {
						async_arg_failed(aCtx, format("Cannot copy object for argument %u of async function call", i + 1));
						engine->ReturnContext(ctx);
						return false;
					}
				}
			}
			if (success < 0) {
				aCtx->SetException(format("Angelscript error %d while setting argument %u in async call to %s", success, i + 1, std::string(func->GetDeclaration())).c_str());
				engine->ReturnContext(ctx);
				return false;
			}
		}
		if (defCtx) engine->ReturnContext(defCtx);
		// Finally our context is actually prepared for execution, which will take place in the thread we're about to spin up.
		duplicate(); // Insure that this object won't get destroyed while the function is executing encase the user chose not to keep a handle to the async_result.
		try {
			if (pool) pool->start(*this);
			else {
				task = angelscript_refcounted_factory<Thread>();
				task->start(*this);
			}
		} catch (...) {
			engine->ReturnContext(ctx);
			release();
			throw;
		}
		return true;
	}
	void run() {
		int result = ctx->Execute();
		if (result == asEXECUTION_ABORTED) exception = "function call aborted";
		else if (result == asEXECUTION_SUSPENDED) exception = "function call suspended";
		else if (result == asEXECUTION_EXCEPTION) exception = ctx->GetExceptionString();
		else if (result == asEXECUTION_FINISHED && subtypeid == asTYPEID_VOID) succeeded = true;
		else if (result == asEXECUTION_FINISHED) {
			// Looking at and being heavily enspired from the scriptgrid addon as I write this.
			// The value is read from where the function left it: the returned object, the returned handle, or the returned number, bool or enum, of its type's size (enum E : int8 takes one byte). A function returning a reference (int& f(), string& f()) leaves the address of the value instead, which is followed here. GetReturnDWord() and the other number getters give 0 for a reference, and GetReturnObject() took a pointer out of the referenced object for the object itself: an int& gave 0, and a string& or a class& was copied from whatever the object's first bytes pointed to.
			void* ret = ctx->GetAddressOfReturnValue();
			if (ret && returns_reference) ret = *(void**)ret;
			asUINT size = (subtypeid & asTYPEID_MASK_OBJECT) ? sizeof(asPWORD) : ctx->GetEngine()->GetSizeOfPrimitiveType(subtypeid);
			value = malloc(size);
			if ((subtypeid & ~asTYPEID_MASK_SEQNBR) && !(subtypeid & asTYPEID_OBJHANDLE)) *(void**)value = ret ? ctx->GetEngine()->CreateScriptObjectCopy(ret, subtype->GetSubType()) : nullptr;
			else if (subtypeid & asTYPEID_OBJHANDLE) {
				*(void**)value = ret ? *(void**)ret : nullptr;
				ctx->GetEngine()->AddRefScriptObject(*(void**)value, subtype->GetSubType());
			} else if (ret) memcpy(value, ret, size);
			else memset(value, 0, size);
			// The copy of a returned object is null when it failed (its copy constructor raised an exception).
			if ((subtypeid & ~asTYPEID_MASK_SEQNBR) && !(subtypeid & asTYPEID_OBJHANDLE) && !*(void**)value) exception = "Cannot copy the return value of async function call";
			else succeeded = true;
		}
		ctx->GetEngine()->ReturnContext(ctx);
		release_value_args();
		progress.set();
		release();
		// This thread's AngelScript data (the list of active contexts and more) was never freed, a leak with every async call made on a thread of its own, which then ends. It is freed last, after release(), which can delete this object and run script destructors here.
		asThreadCleanup();
	}
	void release_value_args() {
		for (const auto& obj : value_args) g_ScriptEngine->ReleaseScriptObject(obj.first, obj.second);
		value_args.clear();
		for (const auto& h : ref_handles) {
			if (*h.first) g_ScriptEngine->ReleaseScriptObject(*h.first, h.second);
		}
		ref_handles.clear();
	}
	bool complete() { return ctx && progress.tryWait(0); }
	bool failed() { return progress.tryWait(0) && !succeeded; }
};
async_result* async_unprepared_factory(asITypeInfo* type) { return new async_result(type); }
void async_factory(asIScriptGeneric* gen) {
	asITypeInfo* ti = *(asITypeInfo**)gen->GetAddressOfArg(0);
	async_result* r = new async_result(ti);
	bool started;
	// call() throws when the thread can't be started, after giving back what it took for the call; the object itself, which nothing else holds yet, was never deleted.
	try {
		started = r->call(gen);
	} catch (...) {
		delete r;
		throw;
	}
	if (!started) delete r;
	else *(async_result**)gen->GetAddressOfReturnLocation() = r;
}

// Poco does support starting a thread by directly passing a function pointer and user data, but things like Poco's ThreadPool do not support this and so instead we opt to inherit from their Runnable class which is more unified and which works with all of Poco's multithreading mechanisms.
class script_runnable : public Runnable {
	asIScriptFunction* func;
	CScriptDictionary* args;
	Thread* thread; // May be null if started from a ThreadPool.
public:
	script_runnable(asIScriptFunction* func, CScriptDictionary* args, Thread* thread = nullptr) : func(func), args(args), thread(thread) {}
	void run() {
		int execution_result = asEXECUTION_FINISHED;
		asIScriptContext* ctx = nullptr;
		if (!func) goto finish;
		ctx = g_ScriptEngine->RequestContext();
		if (!ctx) goto finish;
		if (ctx->Prepare(func) < 0) goto finish;
		if (ctx->SetArgObject(0, args) < 0) goto finish;
		ctx->Execute(); // Todo: Work out what we want to do with exceptions or errors that take place in threads.
	finish:
		if (ctx && !g_shutting_down) g_ScriptEngine->ReturnContext(ctx); // We only do this when the engine is not shutting down because the angelscript could get partially destroyed on the main thread before this point in the shutdown case.
		if (!g_shutting_down) {
			if (args) args->Release();
			if (func) func->Release();
		}
		if (thread) angelscript_refcounted_release<Thread>(thread);
		asThreadCleanup();
		delete this; // Poco wants us to keep these Runnable objects alive as long as the thread is running, meaning we must delete ourself from within the thread to avoid some other sort of cleanup machinery.
		return;
	}
	// For a start that threw before any thread could run us (a pool with no free thread, a thread that is already running): run() will never come to release what we were handed, so the starter does it here.
	void discard() {
		if (args) args->Release();
		if (func) func->Release();
		if (thread) angelscript_refcounted_release<Thread>(thread);
		delete this;
	}
};

void thread_begin(Thread* thread, asIScriptFunction* func, CScriptDictionary* args) {
	if (!func) {
		if (args) args->Release();
		return;
	}
	// Refused here instead of by Poco, whose start() does not give back all of the memory it took when it throws for a thread that is still running.
	if (thread->isRunning()) {
		if (args) args->Release();
		func->Release();
		throw SystemException("thread already running");
	}
	// A run that has finished but was never joined is joined now; Poco's start() would otherwise replace its thread without ever joining it, so that thread would keep its stack until the process ends. Poco marks a thread as no longer running and done in one step, so this never waits, and it does nothing for a thread that was joined already.
	thread->tryJoin(0);
	angelscript_refcounted_duplicate<Thread>(thread);
	script_runnable* runnable = new script_runnable(func, args, thread);
	try {
		thread->start(*runnable);
	} catch (...) {
		// Poco throws after creating the thread only when it fails to apply a priority other than normal, and that thread then runs and frees the runnable itself; at normal priority every failure comes before a thread exists.
		if (thread->getPriority() == Thread::PRIO_NORMAL) runnable->discard();
		throw;
	}
}
// ThreadPool throws, if at all, before it hands the runnable to a worker, so a failed start can always discard it.
template <class F> void pooled_thread_start(asIScriptFunction* func, CScriptDictionary* args, F start) {
	if (!func) {
		if (args) args->Release();
		return;
	}
	script_runnable* runnable = new script_runnable(func, args);
	try {
		start(*runnable);
	} catch (...) {
		runnable->discard();
		throw;
	}
}
void pooled_thread_begin(ThreadPool* pool, asIScriptFunction* func, CScriptDictionary* args) {
	pooled_thread_start(func, args, [pool](Runnable& r) { pool->start(r); });
}
void pooled_thread_begin(ThreadPool* pool, asIScriptFunction* func, CScriptDictionary* args, const std::string& name) {
	pooled_thread_start(func, args, [pool, &name](Runnable& r) { pool->start(r, name); });
}
void pooled_thread_begin(ThreadPool* pool, asIScriptFunction* func, CScriptDictionary* args, Thread::Priority priority) {
	pooled_thread_start(func, args, [pool, priority](Runnable& r) { pool->startWithPriority(priority, r); });
}
void pooled_thread_begin(ThreadPool* pool, asIScriptFunction* func, CScriptDictionary* args, const std::string& name, Thread::Priority priority) {
	pooled_thread_start(func, args, [pool, priority, &name](Runnable& r) { pool->startWithPriority(priority, r, name); });
}

// STL atomics support (thanks @ethindp)!
template<typename...> inline constexpr bool always_false = false;
template <class T, typename... A> void atomics_construct(void* mem, A... args) {
	new (mem) T(args...);
}
template <class T> void atomics_destruct(T* obj) {
	obj->~T();
}
template<typename T> bool is_always_lock_free(T* obj) {
	return obj->is_always_lock_free;
}
template<typename T> void atomic_notify_one(T* obj) { obj->notify_one(); }
// AngelScript compiles a++ and a-- to opPostInc() and opPostDec() without arguments, unlike C++'s operator++(int).
template<typename T> void atomic_notify_all(T* obj) { obj->notify_all(); }
template<typename atomic_type, typename T> T atomic_post_inc(atomic_type* obj) { return (*obj)++; }
template<typename atomic_type, typename T> T atomic_post_dec(atomic_type* obj) { return (*obj)--; }
template<typename T>
consteval const char* as_script_int_name() {
	static_assert(std::is_integral_v<T> && !std::is_same_v<T, bool>);
	if constexpr(!std::is_floating_point_v<T>) {
	constexpr auto s = std::is_signed_v<T>;
	if	  constexpr (sizeof(T) == 1)
		return s ? "int8"  : "uint8";
	else if constexpr (sizeof(T) == 2)
		return s ? "int16" : "uint16";
	else if constexpr (sizeof(T) == 4)
		return s ? "int"   : "uint";
	else if constexpr (sizeof(T) == 8)
		return s ? "int64" : "uint64";
	else
		static_assert(always_false<T>, "value_type has no matching AngelScript primitive");
} else {
if (sizeof(T) == 4)
return "float";
else if (sizeof(T) == 8)
return "double";
else
static_assert(always_false<T>, "value_type has no matching AngelScript primitive");
}
}
template<typename atomic_type, typename divisible_type> void register_atomic_type(asIScriptEngine* engine, const std::string& type_name, const std::string& regular_type_name) {
	// The following functions are available on all atomic types
	engine->RegisterObjectType(type_name.c_str(), sizeof(atomic_type), asOBJ_VALUE | asOBJ_POD | asGetTypeTraits<atomic_type>());
	engine->RegisterObjectBehaviour(type_name.c_str(), asBEHAVE_CONSTRUCT, "void f()", asFUNCTION(atomics_construct<atomic_type>), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour(type_name.c_str(), asBEHAVE_DESTRUCT, "void f()", asFUNCTION(atomics_destruct<atomic_type>), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type_name.c_str(), "bool is_lock_free() const", asMETHODPR(atomic_type, is_lock_free, () const noexcept, bool), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("void store(%s val, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name).c_str(), asMETHODPR(atomic_type, store, (divisible_type, std::memory_order) noexcept, void), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opAssign(%s val)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, operator=, (divisible_type) noexcept, divisible_type), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s load(memory_order order = MEMORY_ORDER_SEQ_CST) const", regular_type_name).c_str(), asMETHODPR(atomic_type, load, (std::memory_order) const noexcept, divisible_type), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opImplConv() const", regular_type_name).c_str(), asMETHODPR(atomic_type, operator divisible_type, () const noexcept, divisible_type), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s exchange(%s desired, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, exchange, (divisible_type, std::memory_order) noexcept, divisible_type), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("bool compare_exchange_weak(%s& expected, %s desired, memory_order success, memory_order failure)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, compare_exchange_weak, (divisible_type&, divisible_type, std::memory_order, std::memory_order) noexcept, bool), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("bool compare_exchange_weak(%s& expected, %s desired, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, compare_exchange_weak, (divisible_type&, divisible_type, std::memory_order) noexcept, bool), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("bool compare_exchange_strong(%s& expected, %s desired, memory_order success, memory_order failure)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, compare_exchange_strong, (divisible_type&, divisible_type, std::memory_order, std::memory_order) noexcept, bool), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("bool compare_exchange_strong(%s& expected, %s desired, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, compare_exchange_strong, (divisible_type&, divisible_type, std::memory_order) noexcept, bool), asCALL_THISCALL);
	engine->RegisterObjectMethod(type_name.c_str(), Poco::format("void wait(%s old, memory_order order = MEMORY_ORDER_SEQ_CST) const", regular_type_name).c_str(), asMETHODPR(atomic_type, wait, (divisible_type, std::memory_order) const noexcept, void), asCALL_THISCALL);
engine->RegisterObjectMethod(type_name.c_str(), "void notify_one()", asFUNCTION(atomic_notify_one<atomic_type>), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type_name.c_str(), "void notify_all()", asFUNCTION(atomic_notify_all<atomic_type>), asCALL_CDECL_OBJFIRST);
	// Begin type-specific atomics
if constexpr((std::is_integral_v<divisible_type>
#ifdef __cpp_lib_atomic_float
		|| std::is_floating_point_v<divisible_type>
#endif
		) && !std::is_same_v<divisible_type, bool>) {
		engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s fetch_add(%s arg, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, fetch_add, (divisible_type, std::memory_order) noexcept, divisible_type), asCALL_THISCALL);
		engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s fetch_sub(%s arg, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, fetch_sub, (divisible_type, std::memory_order) noexcept, divisible_type), asCALL_THISCALL);
		#ifdef __cpp_lib_atomic_min_max // Only available in C++26 mode or later
		if constexpr(std::is_integral_v<divisible_type>) {
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s fetch_max(%s arg, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, fetch_max, (divisible_type, std::memory_order) noexcept, divisible_type), asCALL_THISCALL);
		engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s fetch_min(%s arg, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, fetch_min, (divisible_type, std::memory_order) noexcept, divisible_type), asCALL_THISCALL);
	}
		#endif
		engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opAddAssign(%s arg)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, operator+=, (divisible_type) noexcept, divisible_type), asCALL_THISCALL);
		engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opSubAssign(%s arg)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, operator-=, (divisible_type) noexcept, divisible_type), asCALL_THISCALL);
		if constexpr(std::is_integral_v<divisible_type>) {
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opPreInc()", regular_type_name).c_str(), asMETHODPR(atomic_type, operator++, () noexcept, divisible_type), asCALL_THISCALL);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opPostInc()", regular_type_name).c_str(), asFUNCTION((atomic_post_inc<atomic_type, divisible_type>)), asCALL_CDECL_OBJFIRST);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opPreDec()", regular_type_name).c_str(), asMETHODPR(atomic_type, operator--, () noexcept, divisible_type), asCALL_THISCALL);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opPostDec()", regular_type_name).c_str(), asFUNCTION((atomic_post_dec<atomic_type, divisible_type>)), asCALL_CDECL_OBJFIRST);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s fetch_and(%s arg, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, fetch_and, (divisible_type, std::memory_order) noexcept, divisible_type), asCALL_THISCALL);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s fetch_or(%s arg, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, fetch_or, (divisible_type, std::memory_order) noexcept, divisible_type), asCALL_THISCALL);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s fetch_xor(%s arg, memory_order order = MEMORY_ORDER_SEQ_CST)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, fetch_xor, (divisible_type, std::memory_order) noexcept, divisible_type), asCALL_THISCALL);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opAndAssign(%s arg)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, operator&=, (divisible_type) noexcept, divisible_type), asCALL_THISCALL);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opOrAssign(%s arg)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, operator|=, (divisible_type) noexcept, divisible_type), asCALL_THISCALL);
			engine->RegisterObjectMethod(type_name.c_str(), Poco::format("%s opXorAssign(%s arg)", regular_type_name, regular_type_name).c_str(), asMETHODPR(atomic_type, operator^=, (divisible_type) noexcept, divisible_type), asCALL_THISCALL);
		}
	}
	engine->RegisterObjectMethod(type_name.c_str(), "bool get_is_always_lock_free() property", asFUNCTION(is_always_lock_free<atomic_type>), asCALL_CDECL_OBJFIRST);
}

void RegisterAtomics(asIScriptEngine* engine) {
	// Memory order
	engine->RegisterEnum("memory_order");
	engine->RegisterEnumValue("memory_order", "MEMORY_ORDER_RELAXED", static_cast<std::underlying_type_t<std::memory_order>>(std::memory_order_relaxed));
	engine->RegisterEnumValue("memory_order", "MEMORY_ORDER_ACQUIRE", static_cast<std::underlying_type_t<std::memory_order>>(std::memory_order_acquire));
	engine->RegisterEnumValue("memory_order", "MEMORY_ORDER_RELEASE", static_cast<std::underlying_type_t<std::memory_order>>(std::memory_order_release));
	engine->RegisterEnumValue("memory_order", "MEMORY_ORDER_ACQ_REL", static_cast<std::underlying_type_t<std::memory_order>>(std::memory_order_acq_rel));
	engine->RegisterEnumValue("memory_order", "MEMORY_ORDER_SEQ_CST", static_cast<std::underlying_type_t<std::memory_order>>(std::memory_order_seq_cst));
	// Atomic flag
	engine->RegisterObjectType("atomic_flag", sizeof(std::atomic_flag), asOBJ_VALUE | asOBJ_POD | asGetTypeTraits<std::atomic_flag>());
	engine->RegisterObjectBehaviour("atomic_flag", asBEHAVE_CONSTRUCT, "void f()", asFUNCTION(atomics_construct<std::atomic_flag>), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour("atomic_flag", asBEHAVE_DESTRUCT, "void f()", asFUNCTION(atomics_destruct<std::atomic_flag>), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("atomic_flag", "void clear(memory_order order = MEMORY_ORDER_SEQ_CST)", asMETHODPR(std::atomic_flag, clear, (std::memory_order), void), asCALL_THISCALL);
	engine->RegisterObjectMethod("atomic_flag", "bool test(memory_order order = MEMORY_ORDER_SEQ_CST) const", asMETHODPR(std::atomic_flag, test, (std::memory_order) const noexcept, bool), asCALL_THISCALL);
	engine->RegisterObjectMethod("atomic_flag", "bool test_and_set(memory_order order = MEMORY_ORDER_SEQ_CST)", asMETHODPR(std::atomic_flag, test_and_set, (std::memory_order) noexcept, bool), asCALL_THISCALL);
	engine->RegisterObjectMethod("atomic_flag", "void wait(bool old, memory_order order = MEMORY_ORDER_SEQ_CST) const", asMETHODPR(std::atomic_flag, wait, (bool, std::memory_order) const noexcept, void), asCALL_THISCALL);
	engine->RegisterObjectMethod("atomic_flag", "void notify_one()", asMETHOD(std::atomic_flag, notify_one), asCALL_THISCALL);
	engine->RegisterObjectMethod("atomic_flag", "void notify_all()", asMETHOD(std::atomic_flag, notify_all), asCALL_THISCALL);
	register_atomic_type<std::atomic_int, int>(engine, "atomic_int", "int");
	register_atomic_type<std::atomic_uint, unsigned int>(engine, "atomic_uint", "uint");
	register_atomic_type<std::atomic_int8_t, std::int8_t>(engine, "atomic_int8", "int8");
	register_atomic_type<std::atomic_uint8_t, std::uint8_t>(engine, "atomic_uint8", "uint8");
	register_atomic_type<std::atomic_int16_t, std::int16_t>(engine, "atomic_int16", "int16");
	register_atomic_type<std::atomic_uint16_t, std::uint16_t>(engine, "atomic_uint16", "uint16");
	register_atomic_type<std::atomic_int32_t, std::int32_t>(engine, "atomic_int32", "int32");
	register_atomic_type<std::atomic_uint32_t, std::uint32_t>(engine, "atomic_uint32", "uint32");
	register_atomic_type<std::atomic_int64_t, std::int64_t>(engine, "atomic_int64", "int64");
	register_atomic_type<std::atomic_uint64_t, std::uint64_t>(engine, "atomic_uint64", "uint64");
	register_atomic_type<std::atomic_bool, bool>(engine, "atomic_bool", "bool");
#ifdef __cpp_lib_atomic_lock_free_type_aliases
	register_atomic_type<std::atomic_signed_lock_free, std::atomic_signed_lock_free::value_type>(engine, "atomic_signed_lock_free", as_script_int_name<std::atomic_signed_lock_free::value_type>());
	register_atomic_type<std::atomic_unsigned_lock_free, std::atomic_unsigned_lock_free::value_type>(engine, "atomic_unsigned_lock_free", as_script_int_name<std::atomic_unsigned_lock_free::value_type>());
#endif
	register_atomic_type<std::atomic<float>, float>(engine, "atomic_float", "float");
	register_atomic_type<std::atomic<double>, double>(engine, "atomic_double", "double");
	engine->RegisterGlobalFunction("void atomic_thread_fence(memory_order order)", asFUNCTION(std::atomic_thread_fence), asCALL_CDECL);
}

// A scoped lock (mutex_lock, rw_write_lock...) holds the reference to its mutex that its constructor is given until it is destroyed, and lets go of it after unlocking. The constructor's parameter is declared T@, not T@+, so the reference is the constructor's to keep or let go of: it was never let go of, so every lock leaked a reference to its mutex (a 32-bit count, which after 2^31 locks of one mutex wrapped and freed the mutex while still in use), and a lock of a null rw_lock dereferenced null.
template <class L, class T> struct script_scoped_lock {
	T* target;
	L lock;
	template <typename... A> script_scoped_lock(T* target, A... args) : target(target), lock(*target, args...) {}
};
template <class L, class T, typename... A> void script_scoped_lock_construct(void* mem, T* target, A... args) {
	if (!target) throw NullPointerException("cannot lock a null handle");
	try {
		new (mem) script_scoped_lock<L, T>(target, args...);
	} catch (...) {
		angelscript_refcounted_release<T>(target); // Not locked (a timeout), so nothing holds it.
		throw;
	}
}
template <class L, class T> void script_scoped_lock_destruct(script_scoped_lock<L, T>* mem) {
	T* target = mem->target;
	mem->~script_scoped_lock<L, T>(); // Unlocks first.
	angelscript_refcounted_release<T>(target);
}
template <class T> void script_scoped_lock_unlock(script_scoped_lock<ScopedLockWithUnlock<T>, T>* mem) {
	mem->lock.unlock();
}
template <class T> void mutex_lock_ms(T* mutex, unsigned int ms) {
	mutex->lock(ms);
}
template <class T> bool mutex_try_lock_ms(T* mutex, unsigned int ms) {
	return mutex->tryLock(ms);
}
bool thread_sleep(unsigned int ms) {
	if (!Thread::current()) {
		Thread::sleep(ms);
		return true;
	}
	return Thread::trySleep(ms);
}
// The script's uint fits the OS thread id on every target (a Windows DWORD, a Linux pid_t, an Apple mach port), but Poco returns it
// as a long, which is 8 bytes on 64-bit Linux and Apple targets. Poco has no implementation for Android (it returns 0 for every
// thread there), so the id comes from gettid() on Android.
unsigned int thread_current_id() {
	#ifdef __ANDROID__
	return (unsigned int)gettid();
	#else
	return (unsigned int)Thread::currentOsTid();
	#endif
}
bool thread_try_join(Thread* thread, unsigned int ms) {
	return thread->tryJoin(ms);
}
void event_wait_ms(Event* event, unsigned int ms) {
	event->wait(ms);
}
bool event_try_wait(Event* event, unsigned int ms) {
	return event->tryWait(ms);
}
bool async_try_wait(async_result* result, unsigned int ms) {
	return result->progress.tryWait(ms);
}

template <class T> void RegisterMutexType(asIScriptEngine* engine, const std::string& type) {
	angelscript_refcounted_register<T>(engine, type.c_str());
	if constexpr(std::is_same<T, NamedMutex>::value) engine->RegisterObjectBehaviour(type.c_str(), asBEHAVE_FACTORY, format("%s@ m(const string&in name)", type).c_str(), asFUNCTION((angelscript_refcounted_factory<T, const std::string&>)), asCALL_CDECL);
	else {
		engine->RegisterObjectBehaviour(type.c_str(), asBEHAVE_FACTORY, format("%s@ m()", type).c_str(), asFUNCTION(angelscript_refcounted_factory<T>), asCALL_CDECL);
		engine->RegisterObjectMethod(type.c_str(), _O("void lock(uint milliseconds)"), asFUNCTION(mutex_lock_ms<T>), asCALL_CDECL_OBJFIRST);
		engine->RegisterObjectMethod(type.c_str(), _O("bool try_lock(uint milliseconds)"), asFUNCTION(mutex_try_lock_ms<T>), asCALL_CDECL_OBJFIRST);
	}
	engine->RegisterObjectMethod(type.c_str(), _O("void lock()"), asMETHODPR(T, lock, (), void), asCALL_THISCALL);
	engine->RegisterObjectMethod(type.c_str(), _O("bool try_lock()"), asMETHODPR(T, tryLock, (), bool), asCALL_THISCALL);
	engine->RegisterObjectMethod(type.c_str(), _O("void unlock()"), asMETHOD(T, unlock), asCALL_THISCALL);
	typedef script_scoped_lock<ScopedLockWithUnlock<T>, T> lock_type;
	engine->RegisterObjectType(format("%s_lock", type).c_str(), sizeof(lock_type), asOBJ_VALUE | asGetTypeTraits<lock_type>());
	engine->RegisterObjectBehaviour(format("%s_lock", type).c_str(), asBEHAVE_CONSTRUCT, format("void f(%s@ target)", type).c_str(), asFUNCTION((script_scoped_lock_construct<ScopedLockWithUnlock<T>, T>)), asCALL_CDECL_OBJFIRST);
	if constexpr(!std::is_same<T, NamedMutex>::value) engine->RegisterObjectBehaviour(format("%s_lock", type).c_str(), asBEHAVE_CONSTRUCT, format("void f(%s@ target, uint milliseconds)", type).c_str(), asFUNCTION((script_scoped_lock_construct<ScopedLockWithUnlock<T>, T, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour(format("%s_lock", type).c_str(), asBEHAVE_DESTRUCT, "void f()", asFUNCTION((script_scoped_lock_destruct<ScopedLockWithUnlock<T>, T>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(format("%s_lock", type).c_str(), _O("void unlock()"), asFUNCTION(script_scoped_lock_unlock<T>), asCALL_CDECL_OBJFIRST);
}

static std::thread::id g_main_thread_id;
bool thread_is_main() { return std::this_thread::get_id() == g_main_thread_id; }

void RegisterThreading(asIScriptEngine* engine) {
	g_main_thread_id = std::this_thread::get_id();
	engine->RegisterEnum("thread_priority");
	engine->RegisterEnumValue("thread_priority", "THREAD_PRIORITY_LOWEST", Thread::Priority::PRIO_LOWEST);
	engine->RegisterEnumValue("thread_priority", "THREAD_PRIORITY_LOW", Thread::Priority::PRIO_LOW);
	engine->RegisterEnumValue("thread_priority", "THREAD_PRIORITY_NORMAL", Thread::Priority::PRIO_NORMAL);
	engine->RegisterEnumValue("thread_priority", "THREAD_PRIORITY_HIGH", Thread::Priority::PRIO_HIGH);
	engine->RegisterEnumValue("thread_priority", "THREAD_PRIORITY_HIGHEST", Thread::Priority::PRIO_HIGHEST);
	angelscript_refcounted_register<Thread>(engine, "thread");
	engine->RegisterGlobalFunction("bool get_thread_is_main() property", asFUNCTION(thread_is_main), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("uint thread_current_id()"), asFUNCTION(thread_current_id), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("void thread_yield()"), asFUNCTION(Thread::yield), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("bool thread_sleep(uint ms)"), asFUNCTION(thread_sleep), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("thread@+ get_thread_current() property"), asFUNCTION(Thread::current), asCALL_CDECL);
	engine->RegisterFuncdef(_O("void thread_callback(dictionary@ args)"));
	engine->RegisterObjectBehaviour(_O("thread"), asBEHAVE_FACTORY, _O("thread@ t()"), asFUNCTION(angelscript_refcounted_factory<Thread>), asCALL_CDECL);
	engine->RegisterObjectBehaviour(_O("thread"), asBEHAVE_FACTORY, _O("thread@ t(const string&in name)"), asFUNCTION((angelscript_refcounted_factory<Thread, const std::string&>)), asCALL_CDECL);
	engine->RegisterObjectMethod(_O("thread"), _O("int get_id() const property"), asMETHOD(Thread, id), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread"), _O("void set_priority(thread_priority priority) property"), asMETHOD(Thread, setPriority), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread"), _O("thread_priority get_priority() const property"), asMETHOD(Thread, getPriority), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread"), _O("void set_name(const string&in name) property"), asMETHOD(Thread, setName), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread"), _O("string get_name() const property"), asMETHOD(Thread, getName), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread"), _O("void join()"), asMETHODPR(Thread, join, (), void), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread"), _O("bool join(uint ms)"), asFUNCTION(thread_try_join), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("thread"), _O("bool get_running() const property"), asMETHOD(Thread, isRunning), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread"), _O("void start(thread_callback@ routine, dictionary@ args = null)"), asFUNCTION(thread_begin), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("thread"), _O("void wake_up()"), asMETHOD(Thread, wakeUp), asCALL_THISCALL);
	RegisterMutexType<Mutex>(engine, "mutex");
	RegisterMutexType<FastMutex>(engine, "fast_mutex");
	RegisterMutexType<NamedMutex>(engine, "named_mutex");
	RegisterMutexType<SpinlockMutex>(engine, "spinlock_mutex");
	angelscript_refcounted_register<RWLock>(engine, "rw_lock");
	engine->RegisterObjectBehaviour(_O("rw_lock"), asBEHAVE_FACTORY, _O("rw_lock@ l()"), asFUNCTION(angelscript_refcounted_factory<RWLock>), asCALL_CDECL);
	engine->RegisterObjectMethod(_O("rw_lock"), _O("void read_lock()"), asMETHOD(RWLock, readLock), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("rw_lock"), _O("bool try_read_lock()"), asMETHOD(RWLock, tryReadLock), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("rw_lock"), _O("void write_lock()"), asMETHOD(RWLock, writeLock), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("rw_lock"), _O("bool try_write_lock()"), asMETHOD(RWLock, tryWriteLock), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("rw_lock"), _O("void unlock()"), asMETHOD(RWLock, unlock), asCALL_THISCALL);
	engine->RegisterObjectType("rw_scoped_lock", sizeof(script_scoped_lock<ScopedRWLock, RWLock>), asOBJ_VALUE | asGetTypeTraits<script_scoped_lock<ScopedRWLock, RWLock>>());
	engine->RegisterObjectBehaviour("rw_scoped_lock", asBEHAVE_CONSTRUCT, "void f(rw_lock@ lock, bool write)", asFUNCTION((script_scoped_lock_construct<ScopedRWLock, RWLock, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour("rw_scoped_lock", asBEHAVE_DESTRUCT, "void f()", asFUNCTION((script_scoped_lock_destruct<ScopedRWLock, RWLock>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectType("rw_read_lock", sizeof(script_scoped_lock<ScopedReadRWLock, RWLock>), asOBJ_VALUE | asGetTypeTraits<script_scoped_lock<ScopedReadRWLock, RWLock>>());
	engine->RegisterObjectBehaviour("rw_read_lock", asBEHAVE_CONSTRUCT, "void f(rw_lock@ target)", asFUNCTION((script_scoped_lock_construct<ScopedReadRWLock, RWLock>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour("rw_read_lock", asBEHAVE_DESTRUCT, "void f()", asFUNCTION((script_scoped_lock_destruct<ScopedReadRWLock, RWLock>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectType("rw_write_lock", sizeof(script_scoped_lock<ScopedWriteRWLock, RWLock>), asOBJ_VALUE | asGetTypeTraits<script_scoped_lock<ScopedWriteRWLock, RWLock>>());
	engine->RegisterObjectBehaviour("rw_write_lock", asBEHAVE_CONSTRUCT, "void f(rw_lock@ target)", asFUNCTION((script_scoped_lock_construct<ScopedWriteRWLock, RWLock>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour("rw_write_lock", asBEHAVE_DESTRUCT, "void f()", asFUNCTION((script_scoped_lock_destruct<ScopedWriteRWLock, RWLock>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterEnum("thread_event_type");
	engine->RegisterEnumValue("thread_event_type", "THREAD_EVENT_MANUAL_RESET", Event::EVENT_MANUALRESET);
	engine->RegisterEnumValue("thread_event_type", "THREAD_EVENT_AUTO_RESET", Event::EVENT_AUTORESET);
	angelscript_refcounted_register<Event>(engine, "thread_event");
	engine->RegisterObjectBehaviour("thread_event", asBEHAVE_FACTORY, "thread_event@ e(thread_event_type type = THREAD_EVENT_AUTO_RESET)", asFUNCTION((angelscript_refcounted_factory<Event, Event::EventType>)), asCALL_CDECL);
	engine->RegisterObjectMethod(_O("thread_event"), _O("void set()"), asMETHOD(Event, set), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread_event"), _O("void wait()"), asMETHODPR(Event, wait, (), void), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread_event"), _O("void wait(uint ms)"), asFUNCTION(event_wait_ms), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("thread_event"), _O("bool try_wait(uint ms)"), asFUNCTION(event_try_wait), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("thread_event"), _O("void reset()"), asMETHOD(Event, reset), asCALL_THISCALL);
	angelscript_refcounted_register<ThreadPool>(engine, "thread_pool");
	engine->RegisterObjectBehaviour("thread_pool", asBEHAVE_FACTORY, format("thread_pool@ p(int min_capacity = 2, int max_capacity = 16, int idle_time = 60, int stack_size = %d)", POCO_THREAD_STACK_SIZE).c_str(), asFUNCTION((angelscript_refcounted_factory<ThreadPool, int, int, int, int>)), asCALL_CDECL);
	engine->RegisterObjectMethod("thread_pool", "void add_capacity(int modifier)", asMETHOD(ThreadPool, addCapacity), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "int get_capacity() const property", asMETHOD(ThreadPool, capacity), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "void set_stack_size(int size) property", asMETHOD(ThreadPool, setStackSize), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "int get_stack_size() const property", asMETHOD(ThreadPool, getStackSize), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "int get_used() const property", asMETHOD(ThreadPool, used), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "int get_allocated() const property", asMETHOD(ThreadPool, allocated), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "int get_available() const property", asMETHOD(ThreadPool, available), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("thread_pool"), _O("void start(thread_callback@ routine, dictionary@ args = null)"), asFUNCTIONPR(pooled_thread_begin, (ThreadPool*, asIScriptFunction*, CScriptDictionary*), void), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("thread_pool"), _O("void start(thread_callback@ routine, dictionary@ args, thread_priority priority)"), asFUNCTIONPR(pooled_thread_begin, (ThreadPool*, asIScriptFunction*, CScriptDictionary*, Thread::Priority), void), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("thread_pool"), _O("void start(thread_callback@ routine, dictionary@ args, const string&in name)"), asFUNCTIONPR(pooled_thread_begin, (ThreadPool*, asIScriptFunction*, CScriptDictionary*, const std::string&), void), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("thread_pool"), _O("void start(thread_callback@ routine, dictionary@ args, const string&in name, thread_priority priority)"), asFUNCTIONPR(pooled_thread_begin, (ThreadPool*, asIScriptFunction*, CScriptDictionary*, const std::string&, Thread::Priority), void), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("thread_pool", "void stop_all()", asMETHOD(ThreadPool, stopAll), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "void join_all()", asMETHOD(ThreadPool, joinAll), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "void collect()", asMETHOD(ThreadPool, collect), asCALL_THISCALL);
	engine->RegisterObjectMethod("thread_pool", "const string& get_name() const property", asMETHOD(ThreadPool, name), asCALL_THISCALL);
	engine->RegisterGlobalFunction(_O("thread_pool& get_thread_pool_default() property"), asFUNCTION(ThreadPool::defaultPool), asCALL_CDECL);
	engine->RegisterObjectType("async<class T>", 0, asOBJ_REF | asOBJ_TEMPLATE);
	engine->RegisterObjectBehaviour("async<T>", asBEHAVE_FACTORY, "async<T>@ f(int&in)", asFUNCTION(async_unprepared_factory), asCALL_CDECL);
	std::string filler; // It would seem for now that the best way is to register as many factories as we support number of arguments+1, for a couple of reasons too long to explain in a comment.
	for (int i = 0; i < 16; i++) {
		filler += "const ?&in";
		engine->RegisterObjectBehaviour("async<T>", asBEHAVE_FACTORY, std::string(std::string("async<T>@ f(int&in, ") + filler + ")").c_str(), asFUNCTION(async_factory), asCALL_GENERIC);
		filler += ", ";
	}
	engine->RegisterObjectBehaviour("async<T>", asBEHAVE_ADDREF, "void f()", asMETHODPR(async_result, duplicate, () const, void), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("async<T>", asBEHAVE_RELEASE, "void f()", asMETHODPR(async_result, release, () const, void), asCALL_THISCALL);
	engine->RegisterObjectMethod("async<T>", "const T& get_value() property", asMETHOD(async_result, get_value), asCALL_THISCALL);
	engine->RegisterObjectMethod("async<T>", "bool get_complete() const property", asMETHOD(async_result, complete), asCALL_THISCALL);
	engine->RegisterObjectMethod("async<T>", "bool get_failed() const property", asMETHOD(async_result, failed), asCALL_THISCALL);
	engine->RegisterObjectMethod("async<T>", "string get_exception() const property", asMETHOD(async_result, get_exception), asCALL_THISCALL);
	engine->RegisterObjectMethod("async<T>", "void wait()", asMETHOD(async_result, wait), asCALL_THISCALL);
	engine->RegisterObjectMethod("async<T>", "bool try_wait(uint ms)", asFUNCTION(async_try_wait), asCALL_CDECL_OBJFIRST);
	RegisterAtomics(engine);
}
