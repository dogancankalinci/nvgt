/* random_interface.cpp - object-oriented random number generator implementation
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

#include "random_interface.h"

#include <Poco/Base64Decoder.h>
#include <Poco/Base64Encoder.h>
#include <angelscript.h>
#include <rng_get_bytes.h>
#include <scriptarray.h>

#include <cstring>
#include <sstream>
#include <vector>

#include "random.h"
#include "scriptstuff.h"

// Wrapper class to make script objects compatible with random_interface
class script_random_wrapper : public random_interface {
private:
	asIScriptObject* scriptObj;
	asIScriptFunction* nextFunc;
	asIScriptFunction* next64Func;
	asIScriptFunction* nextfFunc;
	asIScriptFunction* rangeFunc;
	asIScriptFunction* range64Func;
	asIScriptFunction* nextBoolFunc;
	asIScriptFunction* nextCharFunc;
	int32 ref_count;

public:
	script_random_wrapper(asIScriptObject* obj) : scriptObj(obj), ref_count(1) {
		if (scriptObj) {
			scriptObj->AddRef();
			// Get method pointers
			nextFunc = scriptObj->GetObjectType()->GetMethodByDecl("uint next()");
			next64Func = scriptObj->GetObjectType()->GetMethodByDecl("int64 next64()");
			nextfFunc = scriptObj->GetObjectType()->GetMethodByDecl("float nextf()");
			rangeFunc = scriptObj->GetObjectType()->GetMethodByDecl("int range(int, int)");
			range64Func = scriptObj->GetObjectType()->GetMethodByDecl("int64 range64(int64, int64)");
			nextBoolFunc = scriptObj->GetObjectType()->GetMethodByDecl("bool next_bool(int)");
			nextCharFunc = scriptObj->GetObjectType()->GetMethodByDecl("string next_character(const string&in, const string&in)");
		}
	}

	~script_random_wrapper() {
		if (scriptObj)
			scriptObj->Release();
	}

	// Holds the generator while its script runs: set_default_random() in that script lets go of the default generator, and when that was this one, it was deleted together with the context still running the script (a use of freed memory).
	struct running {
		script_random_wrapper* self;
		running(script_random_wrapper* self) : self(self) { self->add_ref(); }
		~running() { self->release(); }
	};
	// Runs one of the generator's methods: as a nested call of the calling script's context when there is one, as NVGT's other
	// callbacks run, else on a pooled context (RequestContextCallback gives it NVGT's line callback, so the generator's statements
	// still count towards a script_function.call()'s limit and the debugger stops at its breakpoints). The wrapper had one context
	// of its own that every call used: random() on two threads at once with a script generator as the default ran both calls on
	// that context at the same time (a crash), and a generator method calling random() itself found the context busy, so that
	// call's Prepare() failed and it returned 0 without running the generator.
	struct call {
		asIScriptObject* obj;
		asIScriptContext* ctx = nullptr;
		bool nested = false, prepared = false;
		call(asIScriptObject* obj, asIScriptFunction* func) : obj(obj) {
			asIScriptContext* active = asGetActiveContext();
			if (script_callbacks_stopped(active)) return; // exit() was called since the calling script began: no more script calls.
			nested = active && active->GetEngine() == obj->GetEngine() && active->PushState() >= 0;
			ctx = nested ? active : obj->GetEngine()->RequestContext();
			if (!ctx) return;
			prepared = ctx->Prepare(func) >= 0 && ctx->SetObject(obj) >= 0;
		}
		bool run() { return prepared && (nested ? execute_nested(ctx) : ctx->Execute()) == asEXECUTION_FINISHED; }
		~call() {
			if (!ctx) return;
			if (!nested) obj->GetEngine()->ReturnContext(ctx);
			else if (prepared) pop_nested_state(ctx); // An exit() in the generator is passed on to the calling script.
			else ctx->PopState();
		}
	};
	uint32 next() override {
		if (!nextFunc) return 0;
		running hold(this);
		call c(scriptObj, nextFunc);
		return c.run() ? c.ctx->GetReturnDWord() : 0;
	}

	float32 nextf() override {
		if (!nextfFunc) return 0.0f;
		running hold(this);
		call c(scriptObj, nextfFunc);
		return c.run() ? c.ctx->GetReturnFloat() : 0.0f;
	}

	int64 next64() override {
		if (!next64Func) return 0;
		running hold(this);
		call c(scriptObj, next64Func);
		return c.run() ? c.ctx->GetReturnQWord() : 0;
	}

	int32 range(int32 min, int32 max) override {
		if (!rangeFunc) return min;
		running hold(this);
		call c(scriptObj, rangeFunc);
		if (c.prepared) {
			c.ctx->SetArgDWord(0, min);
			c.ctx->SetArgDWord(1, max);
		}
		return c.run() ? c.ctx->GetReturnDWord() : 0;
	}

	int64 range64(int64 min, int64 max) override {
		if (!range64Func) return min;
		running hold(this);
		call c(scriptObj, range64Func);
		if (c.prepared) {
			c.ctx->SetArgQWord(0, min);
			c.ctx->SetArgQWord(1, max);
		}
		return c.run() ? c.ctx->GetReturnQWord() : 0;
	}

	void seed(uint32 s) override {
		// Script objects handle their own seeding
	}

	void seed64(uint64 s) override {
		// Script objects handle their own seeding
	}

	std::string get_state() const override {
		return "";  // Script objects handle their own state
	}

	bool set_state(const std::string& state) override {
		return false;  // Script objects handle their own state
	}

	void add_ref() override { asAtomicInc(ref_count); }
	void release() override { if (asAtomicDec(ref_count) < 1) delete this; }
};

// Global default random generator
random_interface* g_default_random = nullptr;
static script_random_wrapper* g_default_script_wrapper = nullptr;
random_xorshift* g_random_xorshift = nullptr;

// Initialize default generator with provided rng
void init_default_random(random_interface* rng) {
	if (rng) {
		g_default_random = rng;
		rng->add_ref();
	}
}

// Initialize default generator
static void ensure_default_random() {
	// Default should always be initialized from RegisterScriptRandom
	if (!g_default_random) {
		// This should never happen in normal operation
		g_default_random = new random_pcg();
	}
}

// The generators below are let go of only once the globals no longer point to them. Letting go of a script generator releases its object, and a script class's destructor run by that release which called random() or set_default_random() reached the generator being deleted: random() ran it again (deleting it a second time once that call returned), and set_default_random() released it a second time.

// Cleanup function to be called before engine shutdown
void cleanup_default_random() {
	random_interface* old_default = g_default_random;
	script_random_wrapper* old_wrapper = g_default_script_wrapper;
	random_xorshift* old_xorshift = g_random_xorshift;
	g_default_random = nullptr;
	g_default_script_wrapper = nullptr;
	g_random_xorshift = nullptr;
	// Be careful not to double-release
	if (old_default && old_default != old_wrapper)
		old_default->release();
	if (old_wrapper)
		old_wrapper->release();
	if (old_xorshift)
		old_xorshift->release();
}

void set_default_random(random_interface* rng) {
	random_interface* old_default = g_default_random;
	if (g_default_script_wrapper && old_default == g_default_script_wrapper)
		g_default_script_wrapper = nullptr;
	g_default_random = rng;
	// The previous default, a generator of its own or the wrapper of a script generator, holds one reference either way.
	if (old_default)
		old_default->release();
}

void set_default_random_script(asIScriptObject* scriptObj) {
	if (!scriptObj) return;
	random_interface* old_default = g_default_random;
	script_random_wrapper* old_wrapper = g_default_script_wrapper;
	// Create wrapper and set as default
	g_default_script_wrapper = new script_random_wrapper(scriptObj);
	g_default_random = g_default_script_wrapper;
	// Clean up previous default
	if (old_default && old_default != old_wrapper)
		old_default->release();
	if (old_wrapper)
		old_wrapper->release();
}

random_interface* get_default_random() {
	ensure_default_random();
	return g_default_random;
}

// Base interface utility functions
bool random_interface::next_bool(int32 percent) {
	if (percent < 1) return false;
	if (percent >= 100) return true;
	return range(0, 99) < percent;
}

std::string random_interface::next_character(const std::string& min, const std::string& max) {
	if (min.empty() || max.empty()) return "";
	if (min == max) return min;
	return std::string(1, static_cast<char>(range(min[0], max[0])));
}

// PCG implementation
random_pcg::random_pcg() : ref_count(1) {
	seed(random_seed());
}

random_pcg::random_pcg(uint32 s) : ref_count(1) {
	seed(s);
}

uint32 random_pcg::next() {
	return rnd_pcg_next(&gen);
}

float32 random_pcg::nextf() {
	return rnd_pcg_nextf(&gen);
}

int32 random_pcg::range(int32 min, int32 max) {
	return rnd_pcg_range(&gen, min, max);
}

void random_pcg::seed(uint32 s) {
	rnd_pcg_seed(&gen, s);
}

std::string random_pcg::get_state() const {
	std::ostringstream ostr;
	Poco::Base64Encoder enc(ostr);
	enc << std::string(reinterpret_cast<const char*>(gen.state), sizeof(gen.state));
	enc.close();
	return ostr.str();
}

bool random_pcg::set_state(const std::string& state) {
	if (state.empty()) {
		seed(random_seed());
		return true;
	}
	std::vector<uint8> r;
	std::istringstream istr(state);
	Poco::Base64Decoder dec(istr);
	char c;
	while (dec.get(c))
		r.push_back(static_cast<uint8>(c));
	if (r.size() != sizeof(gen.state))
		return false;
	memcpy(&gen.state[0], &r[0], sizeof(gen.state));
	return true;
}
void random_pcg::add_ref() { asAtomicInc(ref_count); }
void random_pcg::release() { if (asAtomicDec(ref_count) < 1) delete this; }

// WELL implementation
random_well::random_well() : ref_count(1) {
	seed(random_seed());
}

random_well::random_well(uint32 s) : ref_count(1) {
	seed(s);
}

uint32 random_well::next() {
	return rnd_well_next(&gen);
}

float32 random_well::nextf() {
	return rnd_well_nextf(&gen);
}

int32 random_well::range(int32 min, int32 max) {
	return rnd_well_range(&gen, min, max);
}

void random_well::seed(uint32 s) {
	rnd_well_seed(&gen, s);
}

std::string random_well::get_state() const {
	std::ostringstream ostr;
	Poco::Base64Encoder enc(ostr);
	enc << std::string(reinterpret_cast<const char*>(&gen), sizeof(gen));
	enc.close();
	return ostr.str();
}

bool random_well::set_state(const std::string& state) {
	if (state.empty()) {
		seed(random_seed());
		return true;
	}
	std::vector<uint8> r;
	std::istringstream istr(state);
	Poco::Base64Decoder dec(istr);
	char c;
	while (dec.get(c))
		r.push_back(static_cast<uint8>(c));
	if (r.size() != sizeof(gen))
		return false;
	memcpy(&gen, &r[0], sizeof(gen));
	return true;
}

void random_well::add_ref() { asAtomicInc(ref_count); }
void random_well::release() { if (asAtomicDec(ref_count) < 1) delete this; }

// Gamerand implementation
random_gamerand::random_gamerand() : ref_count(1) {
	seed(random_seed());
}

random_gamerand::random_gamerand(uint32 s) : ref_count(1) {
	seed(s);
}

uint32 random_gamerand::next() {
	return rnd_gamerand_next(&gen);
}

float32 random_gamerand::nextf() {
	return rnd_gamerand_nextf(&gen);
}

int32 random_gamerand::range(int32 min, int32 max) {
	return rnd_gamerand_range(&gen, min, max);
}

void random_gamerand::seed(uint32 s) {
	rnd_gamerand_seed(&gen, s);
}

std::string random_gamerand::get_state() const {
	std::ostringstream ostr;
	Poco::Base64Encoder enc(ostr);
	enc << std::string(reinterpret_cast<const char*>(&gen), sizeof(gen));
	enc.close();
	return ostr.str();
}

bool random_gamerand::set_state(const std::string& state) {
	if (state.empty()) {
		seed(random_seed());
		return true;
	}
	std::vector<uint8> r;
	std::istringstream istr(state);
	Poco::Base64Decoder dec(istr);
	char c;
	while (dec.get(c))
		r.push_back(static_cast<uint8>(c));
	if (r.size() != sizeof(gen))
		return false;
	memcpy(&gen, &r[0], sizeof(gen));
	return true;
}

void random_gamerand::add_ref() { asAtomicInc(ref_count); }
void random_gamerand::release() { if (asAtomicDec(ref_count) < 1) delete this; }

// Xorshift implementation
random_xorshift::random_xorshift() : ref_count(1) {
	uint64_t s;
	rng_get_bytes(reinterpret_cast<unsigned char*>(&s), sizeof(s));
	seed64(s);
}

random_xorshift::random_xorshift(uint64 s) : ref_count(1) {
	seed64(s);
}

uint32 random_xorshift::next() {
	return static_cast<uint32>(rnd_xorshift_next(&gen));
}

int64 random_xorshift::next64() {
	return static_cast<int64>(rnd_xorshift_next(&gen));
}

float32 random_xorshift::nextf() {
	return rnd_xorshift_nextf(&gen);
}

int32 random_xorshift::range(int32 min, int32 max) {
	return rnd_xorshift_range(&gen, min, max);
}

int64 random_xorshift::range64(int64 min, int64 max) {
	return rnd_xorshift_range64(&gen, min, max);
}

void random_xorshift::seed(uint32 s) {
	seed64(static_cast<uint64>(s));
}

void random_xorshift::seed64(uint64 s) {
	rnd_xorshift_seed(&gen, s);
}

std::string random_xorshift::get_state() const {
	std::ostringstream ostr;
	Poco::Base64Encoder enc(ostr);
	enc << std::string(reinterpret_cast<const char*>(&gen), sizeof(gen));
	enc.close();
	return ostr.str();
}

bool random_xorshift::set_state(const std::string& state) {
	if (state.empty()) {
		uint64_t s;
		rng_get_bytes(reinterpret_cast<unsigned char*>(&s), sizeof(s));
		seed64(s);
		return true;
	}
	std::vector<uint8> r;
	std::istringstream istr(state);
	Poco::Base64Decoder dec(istr);
	char c;
	while (dec.get(c))
		r.push_back(static_cast<uint8>(c));
	if (r.size() != sizeof(gen))
		return false;
	memcpy(&gen, &r[0], sizeof(gen));
	return true;
}

void random_xorshift::add_ref() { asAtomicInc(ref_count); }
void random_xorshift::release() { if (asAtomicDec(ref_count) < 1) delete this; }

random_pcg* random_pcg_factory() { return new random_pcg(); }
random_pcg* random_pcg_factory_seed(uint32 seed) { return new random_pcg(seed); }
random_well* random_well_factory() { return new random_well(); }
random_well* random_well_factory_seed(uint32 seed) { return new random_well(seed); }
random_gamerand* random_gamerand_factory() { return new random_gamerand(); }
random_gamerand* random_gamerand_factory_seed(uint32 seed) { return new random_gamerand(seed); }
random_xorshift* random_xorshift_factory() { return new random_xorshift(); }
random_xorshift* random_xorshift_factory_seed_uint(uint32 seed) { return new random_xorshift(static_cast<uint64>(seed)); }
random_xorshift* random_xorshift_factory_seed(uint64 seed) { return new random_xorshift(seed); }

void* random_array_choice(CScriptArray* array, random_interface* rng) {
	if (array->GetSize() == 0) {
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("Cannot get random element from empty array");
		return nullptr;
	}
	if (!rng) rng = get_default_random();
	return array->At(rng->range(0, array->GetSize() - 1));
}

void random_array_choice_wrapper(asIScriptGeneric* gen) {
	CScriptArray* array = (CScriptArray*)gen->GetObject();
	random_interface* rng = (random_interface*)gen->GetArgObject(0);
	void* result = random_array_choice(array, rng);
	if (result)
		gen->SetReturnAddress(result);
	else
		gen->SetReturnAddress(nullptr);
}

// Swaps elements i and j of an array being shuffled, through its temporary last slot. Setting an element of a script class runs its opAssign, script code that can change the array: the objects are held while it runs, as one could be freed under it, and false is returned as soon as the array hasn't the size it is being shuffled at, since the indexes and the temporary slot are those of the array as it was (the final resize removed one of its elements).
static bool shuffle_swap(CScriptArray* array, asUINT size, asUINT i, asUINT j) {
	asITypeInfo* subtype = array->GetArrayObjectType()->GetSubType();
	int type_id = array->GetElementTypeId();
	bool hold = (type_id & asTYPEID_MASK_OBJECT) && !(type_id & asTYPEID_OBJHANDLE) && subtype && (subtype->GetFlags() & asOBJ_REF) && !(subtype->GetFlags() & (asOBJ_NOCOUNT | asOBJ_SCOPED));
	asIScriptEngine* engine = array->GetArrayObjectType()->GetEngine();
	const asUINT moves[3][2] = {{size - 1, i}, {i, j}, {j, size - 1}};
	for (const auto& move : moves) {
		void* to = array->At(move[0]);
		void* from = array->At(move[1]);
		if (hold) {
			engine->AddRefScriptObject(to, subtype);
			engine->AddRefScriptObject(from, subtype);
		}
		array->SetValue(move[0], from);
		if (hold) {
			engine->ReleaseScriptObject(to, subtype);
			engine->ReleaseScriptObject(from, subtype);
		}
		if (array->GetSize() != size) return false;
	}
	return true;
}

// Holds the array being shuffled and the generator shuffling it while script code runs: a generator's range() and an element's opAssign can let go of the last handle to the array, and the default generator's range() can replace it (set_default_random()), and both went on being used after they were freed. AngelScript doesn't hold the object of a registered method for the call.
struct shuffle_hold {
	CScriptArray* array;
	random_interface* rng;
	shuffle_hold(CScriptArray* array, random_interface* rng) : array(array), rng(rng) { array->AddRef(); if (rng) rng->add_ref(); }
	~shuffle_hold() { if (rng) rng->release(); array->Release(); }
};
void random_array_shuffle(CScriptArray* array, random_interface* rng) {
	if (!rng) rng = get_default_random();
	if (array->GetSize() < 2) return;
	shuffle_hold hold(array, rng);
	asIScriptContext* ACtx = asGetActiveContext();
	// Use temporary slot for swapping
	array->Resize(array->GetSize() + 1);
	asUINT size = array->GetSize();
	for (uint32 i = array->GetSize() - 2; i > 0; i--) {
		if (script_callbacks_stopped(ACtx)) break; // exit() was called since the shuffle began, in the script's range() of a generator set with set_default_random() or in an element's opAssign: no more calls, see random_script_array_shuffle().
		int32 j = rng->range(0, i);
		// A generator set with set_default_random() runs the script's range(), which can change the array, see random_script_array_shuffle().
		if (array->GetSize() != size) {
			if (asIScriptContext* active = asGetActiveContext()) active->SetException("the array was changed while it was being shuffled");
			return;
		}
		if (j < 0 || j > int64_t(i)) {
			array->Resize(array->GetSize() - 1);
			if (asIScriptContext* active = asGetActiveContext()) active->SetException("random generator returned an index out of range");
			return;
		}
		if (!shuffle_swap(array, size, i, j)) {
			if (asIScriptContext* active = asGetActiveContext()) active->SetException("the array was changed while it was being shuffled");
			return;
		}
	}
	array->Resize(array->GetSize() - 1);
}

void* random_script_array_choice(CScriptArray* array, asIScriptObject* scriptRng) {
	if (array->GetSize() == 0) {
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("Cannot get random element from empty array");
		return nullptr;
	}
	if (!scriptRng) {
		random_interface* defaultRng = get_default_random();
		return array->At(defaultRng->range(0, array->GetSize() - 1));
	}
	asIScriptEngine* engine = scriptRng->GetEngine();
	asIScriptContext* ctx = engine->CreateContext();
	if (ctx) ctx->SetLineCallback(asFUNCTION(nvgt_line_callback), NULL, asCALL_CDECL); // See script_random_wrapper.
	asIScriptFunction* rangeFunc = scriptRng->GetObjectType()->GetMethodByDecl("int range(int, int)");
	if (rangeFunc && ctx) {
		ctx->Prepare(rangeFunc);
		ctx->SetObject(scriptRng);
		ctx->SetArgDWord(0, 0);
		ctx->SetArgDWord(1, array->GetSize() - 1);
		ctx->Execute();
		int32 index = ctx->GetReturnDWord();
		ctx->Release();
		return array->At(index);
	}
	if (ctx) ctx->Release();
	random_interface* defaultRng = get_default_random();
	return array->At(defaultRng->range(0, array->GetSize() - 1));
}

void random_script_array_choice_wrapper(asIScriptGeneric* gen) {
	CScriptArray* array = (CScriptArray*)gen->GetObject();
	asIScriptObject* scriptRng = (asIScriptObject*)gen->GetArgObject(0);
	void* result = random_script_array_choice(array, scriptRng);
	if (result)
		gen->SetReturnAddress(result);
	else
		gen->SetReturnAddress(nullptr);
}

void random_script_array_shuffle(CScriptArray* array, asIScriptObject* scriptRng) {
	if (!scriptRng) {
		random_interface* defaultRng = get_default_random();
		random_array_shuffle(array, defaultRng);
		return;
	}
	if (array->GetSize() < 2) return;
	shuffle_hold hold(array, nullptr); // The generator is held by the call (@+); see random_array_shuffle().
	asIScriptEngine* engine = scriptRng->GetEngine();
	asIScriptContext* ctx = engine->CreateContext();
	if (ctx) ctx->SetLineCallback(asFUNCTION(nvgt_line_callback), NULL, asCALL_CDECL); // See script_random_wrapper.
	asIScriptFunction* rangeFunc = scriptRng->GetObjectType()->GetMethodByDecl("int range(int, int)");
	asIScriptContext* ACtx = asGetActiveContext();
	if (rangeFunc && ctx) {
		// Use temporary slot for swapping
		array->Resize(array->GetSize() + 1);
		asUINT size = array->GetSize();
		for (uint32 i = array->GetSize() - 2; i > 0; i--) {
			if (script_callbacks_stopped(ACtx)) break; // exit() was called since the shuffle began (in the generator's range(), whose context of its own exit() doesn't abort, or by another thread): no more calls.
			ctx->Prepare(rangeFunc);
			ctx->SetObject(scriptRng);
			ctx->SetArgDWord(0, 0);
			ctx->SetArgDWord(1, i);
			ctx->Execute();
			int32 j = ctx->GetReturnDWord();
			// The generator's range() can change the array. The indexes here are of the array as it was, and At() gives null
			// for an element that is no longer there, which SetValue() then read (a crash for an array of handles or numbers).
			// The temporary slot can't be told apart any more, so it is left.
			if (array->GetSize() != size) {
				ctx->Release();
				if (asIScriptContext* active = asGetActiveContext()) active->SetException("the array was changed while it was being shuffled");
				return;
			}
			if (j < 0 || j > int64_t(i)) {
				array->Resize(array->GetSize() - 1);
				ctx->Release();
				if (asIScriptContext* active = asGetActiveContext()) active->SetException("random generator returned an index out of range");
				return;
			}
			if (!shuffle_swap(array, size, i, j)) {
				ctx->Release();
				if (asIScriptContext* active = asGetActiveContext()) active->SetException("the array was changed while it was being shuffled");
				return;
			}
		}
		array->Resize(array->GetSize() - 1);
		ctx->Release();
	} else {
		if (ctx) ctx->Release();
		random_interface* defaultRng = get_default_random();
		random_array_shuffle(array, defaultRng);
	}
}
