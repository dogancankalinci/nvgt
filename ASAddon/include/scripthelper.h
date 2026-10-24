#ifndef SCRIPTHELPER_H
#define SCRIPTHELPER_H

#include <mutex>
#include <sstream>
#include <string>

#ifndef ANGELSCRIPT_H
// Avoid having to inform include path if header is already include before
#include <angelscript.h>
#endif


BEGIN_AS_NAMESPACE

// Compare relation between two objects of the same type
int CompareRelation(asIScriptEngine *engine, void *lobj, void *robj, int typeId, int &result);

// Compare equality between two objects of the same type
int CompareEquality(asIScriptEngine *engine, void *lobj, void *robj, int typeId, bool &result);

// Compile and execute simple statements
// The module is optional. If given the statements can access the entities compiled in the module.
// The caller can optionally provide its own context, for example if a context should be reused.
int ExecuteString(asIScriptEngine *engine, const char *code, asIScriptModule *mod = 0, asIScriptContext *ctx = 0);

// Compile and execute simple statements with option of return value
// The module is optional. If given the statements can access the entitites compiled in the module.
// The caller can optionally provide its own context, for example if a context should be reused.
// ALTERED: and a namespace to compile the statements in (the module's default namespace is used for them and then put back),
// as the script compiler evaluates a default argument in the namespace of its function
int ExecuteString(asIScriptEngine *engine, const char *code, void *ret, int retTypeId, asIScriptModule *mod = 0, asIScriptContext *ctx = 0, const char *nameSpace = 0);

// Write the registered application interface to a file for an offline compiler.
// The format is compatible with the offline compiler in /sdk/samples/asbuild/.
int WriteConfigToFile(asIScriptEngine *engine, const char *filename);

// Write the registered application interface to a text stream. 
int WriteConfigToStream(asIScriptEngine *engine, std::ostream &strm); 

// Loads an interface from a text stream and configures the engine with it. This will not 
// set the correct function pointers, so it is not possible to use this engine to execute
// scripts, but it can be used to compile scripts and save the byte code.
int ConfigEngineFromStream(asIScriptEngine *engine, std::istream &strm, const char *nameOfStream = "config", asIStringFactory *stringFactory = 0);

// Format the details of the script exception into a human readable text
std::string GetExceptionInfo(asIScriptContext *ctx, bool showStack = false);

// ALTERED: the engine has one message callback for all threads, and the application's code that gathers the messages of a
// build of its own (script_function.call() for default values, script_module's builds, the debugger) replaced it for the time
// of the build and then cleared it: a message of another thread's build went to whichever set it last (two threads added to
// one errors array at once, which corrupted it), or was lost, and the application's own callback was gone for good once the
// first of them had cleared it. Instead, the application's message callback hands a message to the innermost sink the
// calling thread has made, if any (DeliverToScriptMessageSink), and keeps it otherwise. A sink lasts until it is ended or
// destroyed; a sink made inside another one takes the messages until then.
typedef void (*SCRIPT_MESSAGE_SINK_FUNC)(const asSMessageInfo *msg, void *param);
class CScriptMessageSink
{
public:
	CScriptMessageSink(SCRIPT_MESSAGE_SINK_FUNC func, void *param);
	~CScriptMessageSink();
	void End();
private:
	friend bool DeliverToScriptMessageSink(const asSMessageInfo *msg);
	SCRIPT_MESSAGE_SINK_FUNC m_func;
	void *m_param;
	CScriptMessageSink *m_outer;
	bool m_active;
	CScriptMessageSink(const CScriptMessageSink &) = delete;
	CScriptMessageSink &operator=(const CScriptMessageSink &) = delete;
};
// Hands msg to the calling thread's innermost sink, whose function may be null to drop it; false when the thread has none.
bool DeliverToScriptMessageSink(const asSMessageInfo *msg);

// ALTERED: AngelScript builds one thing at a time and refuses another build meanwhile (asBUILD_IN_PROGRESS), and a module's
// default namespace, which ExecuteString sets for the time of its build, is the module's for every thread: a default value
// that script_function.call() or async<T> evaluated while another thread built something failed ("Can't evaluate the default
// value"), or was compiled in the other's namespace. Every build the application makes while scripts run holds this lock for
// the time of the build (not while the code built runs). No script code runs with it held but the destructors of the objects
// in a module's global variables, which a module's rebuild lets go of inside the build, as AngelScript does.
std::recursive_mutex &GetScriptBuildMutex();
// ALTERED: the user data ExecuteString puts on a context the caller gave it: the function ExecuteString built and prepared the
// context with, which it holds a reference to. Letting go of a function frees its id in the engine, which a build on another
// thread takes ids from, so whoever takes this function off the context (ExecuteString, given the context again, and NVGT's
// context pool) unprepares the context first, outside GetScriptBuildMutex(), as what the execution left (its return value,
// its stack after an exception) can have destructors that are script code, and then releases the function under the lock.
const asPWORD EXECUTESTRING_CONTEXT_USER_DATA = 1004;

// Register the exception routines
//  'void throw(const string &msg)'
//  'string getExceptionInfo()'
void RegisterExceptionRoutines(asIScriptEngine *engine);

END_AS_NAMESPACE

#endif
