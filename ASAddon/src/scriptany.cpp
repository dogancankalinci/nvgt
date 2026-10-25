#include "scriptany.h"
#include <new>
#include <assert.h>
#include <string.h>
#include <mutex>

BEGIN_AS_NAMESPACE

// ALTERED: the garbage collector runs on whichever thread is executing script code when it is due, or on a thread of its own,
// so EnumReferences can read an any's value while another thread stores into it. The value and its type are written as one
// (a store, an assignment, the release of the value) under this lock, which EnumReferences takes to read them: it found the
// new value under the old type or the old one under the new type (an integer given to a type's enumeration as an object), and
// a value object (a ref, a dictionaryValue) that the store then freed was given to its type's enumeration (a use after free).
// The locks are shared out by address so that the any keeps its size, and never destroyed, as a collection can still run
// while static objects are being torn down.
static std::mutex &ValueLock(const CScriptAny *any)
{
	static std::mutex *locks = new std::mutex[64];
	asPWORD address = reinterpret_cast<asPWORD>(any);
	return locks[((address >> 4) ^ (address >> 12)) & 63];
}

// We'll use the generic interface for the factories as we need the engine pointer
static void ScriptAnyFactory_Generic(asIScriptGeneric *gen)
{
	asIScriptEngine *engine = gen->GetEngine();

	*(CScriptAny**)gen->GetAddressOfReturnLocation() = new CScriptAny(engine);
}

static void ScriptAnyFactory2_Generic(asIScriptGeneric *gen)
{
	asIScriptEngine *engine = gen->GetEngine();
	void *ref = (void*)gen->GetArgAddress(0);
	int refType = gen->GetArgTypeId(0);

	*(CScriptAny**)gen->GetAddressOfReturnLocation() = new CScriptAny(ref,refType,engine);
}

static CScriptAny &ScriptAnyAssignment(CScriptAny *other, CScriptAny *self)
{
	return *self = *other;
}

static void ScriptAnyAssignment_Generic(asIScriptGeneric *gen)
{
	CScriptAny *other = (CScriptAny*)gen->GetArgObject(0);
	CScriptAny *self = (CScriptAny*)gen->GetObject();

	*self = *other;

	gen->SetReturnObject(self);
}

static void ScriptAny_Store_Generic(asIScriptGeneric *gen)
{
	void *ref = (void*)gen->GetArgAddress(0);
	int refTypeId = gen->GetArgTypeId(0);
	CScriptAny *self = (CScriptAny*)gen->GetObject();

	self->Store(ref, refTypeId);
}

static void ScriptAny_StoreInt_Generic(asIScriptGeneric *gen)
{
	asINT64 *ref = (asINT64*)gen->GetArgAddress(0);
	CScriptAny *self = (CScriptAny*)gen->GetObject();

	self->Store(*ref);
}

static void ScriptAny_StoreFlt_Generic(asIScriptGeneric *gen)
{
	double *ref = (double*)gen->GetArgAddress(0);
	CScriptAny *self = (CScriptAny*)gen->GetObject();

	self->Store(*ref);
}

static void ScriptAny_Retrieve_Generic(asIScriptGeneric *gen)
{
	void *ref = (void*)gen->GetArgAddress(0);
	int refTypeId = gen->GetArgTypeId(0);
	CScriptAny *self = (CScriptAny*)gen->GetObject();

	*(bool*)gen->GetAddressOfReturnLocation() = self->Retrieve(ref, refTypeId);
}

static void ScriptAny_RetrieveInt_Generic(asIScriptGeneric *gen)
{
	asINT64 *ref = (asINT64*)gen->GetArgAddress(0);
	CScriptAny *self = (CScriptAny*)gen->GetObject();

	*(bool*)gen->GetAddressOfReturnLocation() = self->Retrieve(*ref);
}

static void ScriptAny_RetrieveFlt_Generic(asIScriptGeneric *gen)
{
	double *ref = (double*)gen->GetArgAddress(0);
	CScriptAny *self = (CScriptAny*)gen->GetObject();

	*(bool*)gen->GetAddressOfReturnLocation() = self->Retrieve(*ref);
}

static void ScriptAny_AddRef_Generic(asIScriptGeneric *gen)
{
	CScriptAny *self = (CScriptAny*)gen->GetObject();
	self->AddRef();
}

static void ScriptAny_Release_Generic(asIScriptGeneric *gen)
{
	CScriptAny *self = (CScriptAny*)gen->GetObject();
	self->Release();
}

static void ScriptAny_GetRefCount_Generic(asIScriptGeneric *gen)
{
	CScriptAny *self = (CScriptAny*)gen->GetObject();
	*(int*)gen->GetAddressOfReturnLocation() = self->GetRefCount();
}

static void ScriptAny_SetFlag_Generic(asIScriptGeneric *gen)
{
	CScriptAny *self = (CScriptAny*)gen->GetObject();
	self->SetFlag();
}

static void ScriptAny_GetFlag_Generic(asIScriptGeneric *gen)
{
	CScriptAny *self = (CScriptAny*)gen->GetObject();
	*(bool*)gen->GetAddressOfReturnLocation() = self->GetFlag();
}

static void ScriptAny_EnumReferences_Generic(asIScriptGeneric *gen)
{
	CScriptAny *self = (CScriptAny*)gen->GetObject();
	asIScriptEngine *engine = *(asIScriptEngine**)gen->GetAddressOfArg(0);
	self->EnumReferences(engine);
}

static void ScriptAny_ReleaseAllHandles_Generic(asIScriptGeneric *gen)
{
	CScriptAny *self = (CScriptAny*)gen->GetObject();
	asIScriptEngine *engine = *(asIScriptEngine**)gen->GetAddressOfArg(0);
	self->ReleaseAllHandles(engine);
}

void RegisterScriptAny(asIScriptEngine *engine)
{
	if( strstr(asGetLibraryOptions(), "AS_MAX_PORTABILITY") )
		RegisterScriptAny_Generic(engine);
	else
		RegisterScriptAny_Native(engine);
}

void RegisterScriptAny_Native(asIScriptEngine *engine)
{
	int r;
	r = engine->RegisterObjectType("any", sizeof(CScriptAny), asOBJ_REF | asOBJ_GC); assert( r >= 0 );

	// We'll use the generic interface for the constructor as we need the engine pointer
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_FACTORY, "any@ f()", asFUNCTION(ScriptAnyFactory_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_FACTORY, "any@ f(?&in value)", asFUNCTION(ScriptAnyFactory2_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_FACTORY, "any@ f(const int64&in value)", asFUNCTION(ScriptAnyFactory2_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_FACTORY, "any@ f(const double&in value)", asFUNCTION(ScriptAnyFactory2_Generic), asCALL_GENERIC); assert(r >= 0);

	r = engine->RegisterObjectBehaviour("any", asBEHAVE_ADDREF, "void f()", asMETHOD(CScriptAny,AddRef), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_RELEASE, "void f()", asMETHOD(CScriptAny,Release), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "any &opAssign(any&in other)", asFUNCTION(ScriptAnyAssignment), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "void store(?&in value)", asMETHODPR(CScriptAny,Store,(void*,int),void), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "void store(const int64&in value)", asMETHODPR(CScriptAny,Store,(asINT64&),void), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "void store(const double&in value)", asMETHODPR(CScriptAny,Store,(double&),void), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "bool retrieve(?&out value)", asMETHODPR(CScriptAny,Retrieve,(void*,int) const,bool), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "bool retrieve(int64&out value)", asMETHODPR(CScriptAny,Retrieve,(asINT64&) const,bool), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "bool retrieve(double&out value)", asMETHODPR(CScriptAny,Retrieve,(double&) const,bool), asCALL_THISCALL); assert( r >= 0 );

	// Register GC behaviours
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_GETREFCOUNT, "int f()", asMETHOD(CScriptAny,GetRefCount), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_SETGCFLAG, "void f()", asMETHOD(CScriptAny,SetFlag), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_GETGCFLAG, "bool f()", asMETHOD(CScriptAny,GetFlag), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_ENUMREFS, "void f(int&in)", asMETHOD(CScriptAny,EnumReferences), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_RELEASEREFS, "void f(int&in)", asMETHOD(CScriptAny,ReleaseAllHandles), asCALL_THISCALL); assert( r >= 0 );
}

void RegisterScriptAny_Generic(asIScriptEngine *engine)
{
	int r;
	r = engine->RegisterObjectType("any", sizeof(CScriptAny), asOBJ_REF | asOBJ_GC); assert( r >= 0 );

	// We'll use the generic interface for the constructor as we need the engine pointer
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_FACTORY, "any@ f()", asFUNCTION(ScriptAnyFactory_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_FACTORY, "any@ f(?&in value) explicit", asFUNCTION(ScriptAnyFactory2_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_FACTORY, "any@ f(const int64&in value) explicit", asFUNCTION(ScriptAnyFactory2_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_FACTORY, "any@ f(const double&in value) explicit", asFUNCTION(ScriptAnyFactory2_Generic), asCALL_GENERIC); assert(r >= 0);

	r = engine->RegisterObjectBehaviour("any", asBEHAVE_ADDREF, "void f()", asFUNCTION(ScriptAny_AddRef_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_RELEASE, "void f()", asFUNCTION(ScriptAny_Release_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "any &opAssign(any&in other)", asFUNCTION(ScriptAnyAssignment_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "void store(?&in value)", asFUNCTION(ScriptAny_Store_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "void store(const int64&in value)", asFUNCTION(ScriptAny_StoreInt_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "void store(const double&in value)", asFUNCTION(ScriptAny_StoreFlt_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "bool retrieve(?&out value) const", asFUNCTION(ScriptAny_Retrieve_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "bool retrieve(int64&out value) const", asFUNCTION(ScriptAny_RetrieveInt_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("any", "bool retrieve(double&out value) const", asFUNCTION(ScriptAny_RetrieveFlt_Generic), asCALL_GENERIC); assert( r >= 0 );

	// Register GC behaviours
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_GETREFCOUNT, "int f()", asFUNCTION(ScriptAny_GetRefCount_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_SETGCFLAG, "void f()", asFUNCTION(ScriptAny_SetFlag_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_GETGCFLAG, "bool f()", asFUNCTION(ScriptAny_GetFlag_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_ENUMREFS, "void f(int&in)", asFUNCTION(ScriptAny_EnumReferences_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("any", asBEHAVE_RELEASEREFS, "void f(int&in)", asFUNCTION(ScriptAny_ReleaseAllHandles_Generic), asCALL_GENERIC); assert( r >= 0 );
}


// Releases a value that the any no longer holds: its object or handle and its type's reference
static void ReleaseAnyValue(asIScriptEngine *engine, void *obj, int typeId)
{
	if( typeId & asTYPEID_MASK_OBJECT )
	{
		asITypeInfo *ti = engine->GetTypeInfoById(typeId);
		engine->ReleaseScriptObject(obj, ti);
		if( ti )
			ti->Release();
	}
}

// ALTERED: holds an any and the object it stores while that object is copied out of it (a script class's copy constructor or
// opAssign), which can store another value into the any or empty it: the object was released and freed in the middle of its
// own copy, which went on reading it. Only an object whose type counts references is held (not a value type, nor a scoped or
// NOCOUNT one). The any itself is held as the copy can let go of it too.
struct SAnyValueHold
{
	const CScriptAny *any;
	asIScriptEngine *engine;
	asITypeInfo *type;
	void *obj;
	SAnyValueHold(const CScriptAny *any, asIScriptEngine *engine, void *obj, int typeId) : any(any), engine(engine), type(0), obj(0)
	{
		any->AddRef();
		asITypeInfo *ti = obj && (typeId & asTYPEID_MASK_OBJECT) ? engine->GetTypeInfoById(typeId) : 0;
		if( ti && (ti->GetFlags() & asOBJ_REF) && !(ti->GetFlags() & (asOBJ_NOCOUNT | asOBJ_SCOPED)) )
		{
			this->type = ti;
			this->obj = obj;
			engine->AddRefScriptObject(obj, ti);
		}
	}
	~SAnyValueHold()
	{
		if( obj )
			engine->ReleaseScriptObject(obj, type);
		any->Release();
	}
};

CScriptAny &CScriptAny::operator=(const CScriptAny &other)
{
	// ALTERED: assigning an any to itself (a = a) released its value before copying it from itself, which left it empty and
	// leaked the reference to the value's type taken below (the module then couldn't free that type)
	if( &other == this )
		return *this;

	// ALTERED: the new value is made first and the previous one released last, once the any holds the new one. The previous
	// value was released while the any still held it, so a destructor run by that release that stored into or cleared this
	// same any released it a second time (freed during its own destructor) and its type with it.
	// The any is held until it holds the new value, as the copy below can let go of it, see SAnyValueHold.
	SAnyValueHold holdThis(this, engine, 0, 0);
	valueStruct nv;
	nv.valueInt = 0;
	nv.typeId = other.value.typeId;

	// Hold on to the object type reference so it isn't destroyed too early
	if( (nv.typeId & asTYPEID_MASK_OBJECT) )
	{
		asITypeInfo *ti = engine->GetTypeInfoById(nv.typeId);
		if( ti )
			ti->AddRef();
	}

	if( nv.typeId & asTYPEID_OBJHANDLE )
	{
		// For handles, copy the pointer and increment the reference count
		nv.valueObj = other.value.valueObj;
		engine->AddRefScriptObject(nv.valueObj, engine->GetTypeInfoById(nv.typeId));
	}
	else if( nv.typeId & asTYPEID_MASK_OBJECT )
	{
		// Create a copy of the object
		SAnyValueHold hold(&other, engine, other.value.valueObj, nv.typeId); // ALTERED: see SAnyValueHold
		nv.valueObj = engine->CreateScriptObjectCopy(other.value.valueObj, engine->GetTypeInfoById(nv.typeId));
	}
	else
	{
		// Primitives can be copied directly
		nv.valueInt = other.value.valueInt;
	}

	valueStruct old;
	{
		std::lock_guard<std::mutex> guard(ValueLock(this)); // ALTERED: see ValueLock
		old = value;
		value = nv;
	}
	ReleaseAnyValue(engine, old.valueObj, old.typeId);

	return *this;
}

int CScriptAny::CopyFrom(const CScriptAny *other)
{
	if( other == 0 ) return asINVALID_ARG;

	*this = *(CScriptAny*)other;

	return 0;
}

CScriptAny::CScriptAny(asIScriptEngine *engine)
{
	this->engine = engine;
	refCount = 1;
	gcFlag = false;

	value.typeId = 0;
	value.valueInt = 0;

	// Notify the garbage collector of this object
	engine->NotifyGarbageCollectorOfNewObject(this, engine->GetTypeInfoByName("any"));
}

CScriptAny::CScriptAny(void *ref, int refTypeId, asIScriptEngine *engine)
{
	this->engine = engine;
	refCount = 1;
	gcFlag = false;

	value.typeId = 0;
	value.valueInt = 0;

	// Notify the garbage collector of this object
	engine->NotifyGarbageCollectorOfNewObject(this, engine->GetTypeInfoByName("any"));

	Store(ref, refTypeId);
}

CScriptAny::~CScriptAny()
{
	FreeObject();
}

void CScriptAny::Store(void *ref, int refTypeId)
{
	// This method is not expected to be used for primitive types, except for bool, int64, or double
	assert( refTypeId > asTYPEID_DOUBLE || refTypeId == asTYPEID_VOID || refTypeId == asTYPEID_BOOL || refTypeId == asTYPEID_INT64 || refTypeId == asTYPEID_DOUBLE );

	// ALTERED: the new value is made first and the previous one released last, as in operator=
	// The any is held until it holds the new value, see SAnyValueHold: the copy of an object below (a script class's copy
	// constructor) that let go of the any (gany.store(c) where the copy constructor runs @gany = null) freed it in the middle of
	// the store, which then wrote the new value into the freed any.
	SAnyValueHold holdThis(this, engine, 0, 0);
	valueStruct nv;
	nv.valueInt = 0;
	nv.typeId = refTypeId;

	// Hold on to the object type reference so it isn't destroyed too early
	if( (refTypeId & asTYPEID_MASK_OBJECT) )
	{
		asITypeInfo *ti = engine->GetTypeInfoById(refTypeId);
		if( ti )
			ti->AddRef();
	}

	if( nv.typeId & asTYPEID_OBJHANDLE )
	{
		// We're receiving a reference to the handle, so we need to dereference it
		nv.valueObj = *(void**)ref;
		engine->AddRefScriptObject(nv.valueObj, engine->GetTypeInfoById(nv.typeId));
	}
	else if( nv.typeId & asTYPEID_MASK_OBJECT )
	{
		// Create a copy of the object
		// ALTERED: the object being copied is held for its copy too, as the copy can free it (an element of an array the copy
		// constructor empties), see SAnyValueHold
		SAnyValueHold hold(this, engine, ref, nv.typeId);
		nv.valueObj = engine->CreateScriptObjectCopy(ref, engine->GetTypeInfoById(nv.typeId));
	}
	else
	{
		// Copy the primitive value
		// We receive a pointer to the value.
		int size = engine->GetSizeOfPrimitiveType(nv.typeId);
		memcpy(&nv.valueInt, ref, size);
	}

	valueStruct old;
	{
		std::lock_guard<std::mutex> guard(ValueLock(this)); // ALTERED: see ValueLock
		old = value;
		value = nv;
	}
	ReleaseAnyValue(engine, old.valueObj, old.typeId);
}

void CScriptAny::Store(double &ref)
{
	Store(&ref, asTYPEID_DOUBLE);
}

void CScriptAny::Store(asINT64 &ref)
{
	Store(&ref, asTYPEID_INT64);
}


bool CScriptAny::Retrieve(void *ref, int refTypeId) const
{
	// This method is not expected to be used for primitive types, except for bool, int64, or double
	assert( refTypeId > asTYPEID_DOUBLE || refTypeId == asTYPEID_BOOL || refTypeId == asTYPEID_INT64 || refTypeId == asTYPEID_DOUBLE );

	if( refTypeId & asTYPEID_OBJHANDLE )
	{
		// Is the handle type compatible with the stored value?

		// A handle can be retrieved if the stored type is a handle of same or compatible type
		// or if the stored type is an object that implements the interface that the handle refer to.
		if( (value.typeId & asTYPEID_MASK_OBJECT) )
		{
			// Don't allow the retrieval if the stored handle is to a const object but not the wanted handle
			if( (value.typeId & asTYPEID_HANDLETOCONST) && !(refTypeId & asTYPEID_HANDLETOCONST) )
				return false;

			// RefCastObject will increment the refCount of the returned pointer if successful
			engine->RefCastObject(value.valueObj, engine->GetTypeInfoById(value.typeId), engine->GetTypeInfoById(refTypeId), reinterpret_cast<void**>(ref));
			if( *(asPWORD*)ref == 0 )
				return false;
			return true;
		}
	}
	else if( refTypeId & asTYPEID_MASK_OBJECT )
	{
		// Is the object type compatible with the stored value?

		// Copy the object into the given reference
		if( value.typeId == refTypeId )
		{
			// ALTERED: an any whose value's copy failed (its copy constructor or opAssign raised when it was stored or assigned
			// from another any) holds the value's type with no object, and there is nothing to retrieve: AssignScriptObject
			// refused the null object, and true was returned with nothing given (the caller got the &out temporary, a
			// default-made object, as the value)
			if( value.valueObj == 0 )
				return false;
			SAnyValueHold hold(this, engine, value.valueObj, value.typeId); // ALTERED: see SAnyValueHold
			engine->AssignScriptObject(ref, hold.obj ? hold.obj : value.valueObj, engine->GetTypeInfoById(refTypeId));
			return true;
		}
	}
	else
	{
		// Is the primitive type compatible with the stored value?

		if( value.typeId == refTypeId )
		{
			int size = engine->GetSizeOfPrimitiveType(refTypeId);
			memcpy(ref, &value.valueInt, size);
			return true;
		}

		// We know all numbers are stored as either int64 or double, since we register overloaded functions for those
		if( value.typeId == asTYPEID_INT64 && refTypeId == asTYPEID_DOUBLE )
		{
			*(double*)ref = double(value.valueInt);
			return true;
		}
		else if( value.typeId == asTYPEID_DOUBLE && refTypeId == asTYPEID_INT64 )
		{
			*(asINT64*)ref = asINT64(value.valueFlt);
			return true;
		}
	}

	return false;
}

bool CScriptAny::Retrieve(asINT64 &outValue) const
{
	return Retrieve(&outValue, asTYPEID_INT64);
}

bool CScriptAny::Retrieve(double &outValue) const
{
	return Retrieve(&outValue, asTYPEID_DOUBLE);
}

int CScriptAny::GetTypeId() const
{
	return value.typeId;
}

void* CScriptAny::GetAddressOfValue() const
{
	return value.valueObj;
}

void CScriptAny::FreeObject()
{
	// If it is a handle or a ref counted object, call release
	if( value.typeId & asTYPEID_MASK_OBJECT )
	{
		// ALTERED: the any is emptied before the object is released, not after (see operator=)
		void *obj;
		int typeId;
		{
			std::lock_guard<std::mutex> guard(ValueLock(this)); // ALTERED: see ValueLock
			obj = value.valueObj;
			typeId = value.typeId;
			value.valueObj = 0;
			value.typeId = 0;
		}

		// Let the engine release the object and the object type info
		ReleaseAnyValue(engine, obj, typeId);
	}

	// For primitives, there's nothing to do
}


void CScriptAny::EnumReferences(asIScriptEngine *inEngine)
{
	// ALTERED: the value and its type are read under the any's lock, see ValueLock
	std::lock_guard<std::mutex> guard(ValueLock(this));

	// If we're holding a reference, we'll notify the garbage collector of it
	if (value.valueObj && (value.typeId & asTYPEID_MASK_OBJECT))
	{
		asITypeInfo *subType = engine->GetTypeInfoById(value.typeId);
		if ((subType->GetFlags() & asOBJ_REF))
		{
			inEngine->GCEnumCallback(value.valueObj);
		}
		else if ((subType->GetFlags() & asOBJ_VALUE) && (subType->GetFlags() & asOBJ_GC))
		{
			// For value types we need to forward the enum callback
			// to the object so it can decide what to do
			engine->ForwardGCEnumReferences(value.valueObj, subType);
		}

		// The object type itself is also garbage collected
		asITypeInfo *ti = inEngine->GetTypeInfoById(value.typeId);
		if (ti)
			inEngine->GCEnumCallback(ti);
	}
}

void CScriptAny::ReleaseAllHandles(asIScriptEngine * /*engine*/)
{
	FreeObject();
}

int CScriptAny::AddRef() const
{
	// Increase counter and clear flag set by GC
	gcFlag = false;
	return asAtomicInc(refCount);
}

int CScriptAny::Release() const
{
	// Decrease the ref counter
	gcFlag = false;
	if( asAtomicDec(refCount) == 0 )
	{
		// Delete this object as no more references to it exists
		delete this;
		return 0;
	}

	return refCount;
}

int CScriptAny::GetRefCount()
{
	return refCount;
}

void CScriptAny::SetFlag()
{
	gcFlag = true;
}

bool CScriptAny::GetFlag()
{
	return gcFlag;
}


END_AS_NAMESPACE
