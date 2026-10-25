#include <assert.h>
#include <string.h>
#include <mutex>
#include <vector>
#include "scriptdictionary.h"
#include "scriptarray.h"

BEGIN_AS_NAMESPACE

using namespace std;

// The garbage collector runs on whichever thread is executing script code when it is due, or on a thread of its own,
// so EnumReferences can walk a dictionary while another thread adds or removes keys, which reallocates the hash table
// and frees nodes. Changing the set of keys and walking it therefore take the dictionary's lock. The locks are shared
// out by address so that the dictionary object keeps its size, and they are never destroyed, as a collection can
// still run while static objects are being torn down.
static std::mutex &StructureLock(const void *dictionary)
{
	static std::mutex *locks = new std::mutex[64];
	asPWORD address = reinterpret_cast<asPWORD>(dictionary);
	return locks[((address >> 4) ^ (address >> 12)) & 63];
}

// ALTERED: a value (a dictionary's entry, or a dictionaryValue of its own) changed in place by a script (d['k'] = v, through
// the reference opIndex returns) is not changed through its dictionary, so StructureLock can't be taken for it. Its value
// and type are swapped under this lock, which the collector takes to read them (CScriptDictionary::EnumReferences takes it
// for each entry within StructureLock, CScriptDictValue::EnumReferences for itself): it found the new value under the old
// type or the old value under the new one, and a value object (a ref, a dictionaryValue) that the assignment then freed was
// given to its type's enumeration (a use after free). The locks are shared out by address, never destroyed (see
// StructureLock), and recursive: the enumeration of an entry holding a dictionaryValue takes the lock of that value too.
static std::recursive_mutex &ValueLock(const CScriptDictValue *value)
{
	static std::recursive_mutex *locks = new std::recursive_mutex[64];
	asPWORD address = reinterpret_cast<asPWORD>(value);
	return locks[((address >> 4) ^ (address >> 12)) & 63];
}

// ALTERED: holds a dictionary while script code runs for it (the copy of a value, see CScriptDictionary::Set), which can let go
// of its last handle. AngelScript doesn't hold the object of a registered method for the call (only when the method returns a
// reference).
struct SDictionaryHold
{
	const CScriptDictionary *dict;
	SDictionaryHold(const CScriptDictionary *dict) : dict(dict) { dict->AddRef(); }
	~SDictionaryHold() { dict->Release(); }
};

// ALTERED: holds a value's object while it is copied or assigned (script code: a copy constructor, opAssign, opCast), which
// can take it out of the dictionary that held it and free it in the middle of its own copy. Only an object whose type counts
// references is held: a scoped type (asOBJ_SCOPED) has a release behaviour that destroys it, and a value type is not
// reference counted.
struct SDictObjectHold
{
	asIScriptEngine *engine;
	asITypeInfo *type;
	void *obj;
	SDictObjectHold(asIScriptEngine *engine, void *obj, int typeId) : engine(engine), type(0), obj(0)
	{
		asITypeInfo *ti = obj && (typeId & asTYPEID_MASK_OBJECT) ? engine->GetTypeInfoById(typeId) : 0;
		if( ti && (ti->GetFlags() & asOBJ_REF) && !(ti->GetFlags() & (asOBJ_NOCOUNT | asOBJ_SCOPED)) )
		{
			this->type = ti;
			this->obj = obj;
			engine->AddRefScriptObject(obj, ti);
		}
	}
	~SDictObjectHold() { if( obj ) engine->ReleaseScriptObject(obj, type); }
};

// ALTERED: an enum is of its underlying type's size and signedness (enum E : int8 takes one byte, enum E : uint64 eight).
// Every enum was read and written here as a 32-bit int: get() into an 8-byte enum set only its low half and left the upper
// one as it was (-7 read back as 8589934585, or as 4294967289 by script_function.call()), the value of an 8-byte enum was
// read as its low half, and that of a 1 or 2-byte enum together with whatever bytes followed it in the stored value.
static asINT64 EnumToInt64(asIScriptEngine *engine, int enumTypeId, const void *src)
{
	asITypeInfo *ti = engine->GetTypeInfoById(enumTypeId);
	switch( ti ? ti->GetUnderlyingTypeId() : asTYPEID_INT32 )
	{
	case asTYPEID_INT8:   return *(const asINT8*)src;
	case asTYPEID_INT16:  return *(const asINT16*)src;
	case asTYPEID_INT64:  return *(const asINT64*)src;
	case asTYPEID_UINT8:  return *(const asBYTE*)src;
	case asTYPEID_UINT16: return *(const asWORD*)src;
	case asTYPEID_UINT32: return *(const asDWORD*)src;
	case asTYPEID_UINT64: return asINT64(*(const asQWORD*)src);
	default:              return *(const int*)src;
	}
}
static void Int64ToEnum(asIScriptEngine *engine, int enumTypeId, asINT64 value, void *dst)
{
	switch( engine->GetSizeOfPrimitiveType(enumTypeId) )
	{
	case 1:  *(asBYTE*)dst = asBYTE(value); break;
	case 2:  *(asWORD*)dst = asWORD(value); break;
	case 8:  *(asINT64*)dst = value; break;
	default: *(int*)dst = int(value); break;
	}
}

//------------------------------------------------------------------------
// Object types are cached as user data to avoid costly runtime lookups

// We just define a number here that we assume nobody else is using for
// object type user data. The add-ons have reserved the numbers 1000
// through 1999 for this purpose, so we should be fine.
const asPWORD DICTIONARY_CACHE = 1003;

// This cache holds the object type of the dictionary type and array type
// so it isn't necessary to look this up each time the dictionary or array
// is created.
struct SDictionaryCache
{
	asITypeInfo *dictType;
	asITypeInfo *arrayType;
	asITypeInfo *keyType;

	// This is called from RegisterScriptDictionary
	static void Setup(asIScriptEngine *engine)
	{
		SDictionaryCache *cache = reinterpret_cast<SDictionaryCache*>(engine->GetUserData(DICTIONARY_CACHE));
		if( cache == 0 )
		{
			cache = new SDictionaryCache;
			engine->SetUserData(cache, DICTIONARY_CACHE);
			engine->SetEngineUserDataCleanupCallback(SDictionaryCache::Cleanup, DICTIONARY_CACHE);

			cache->dictType = engine->GetTypeInfoByName("dictionary");
			cache->arrayType = engine->GetTypeInfoByDecl("array<string>");
			cache->keyType = engine->GetTypeInfoByDecl("string");
		}
	}

	// This is called from the engine when shutting down
	static void Cleanup(asIScriptEngine *engine)
	{
		SDictionaryCache *cache = reinterpret_cast<SDictionaryCache*>(engine->GetUserData(DICTIONARY_CACHE));
		if( cache )
			delete cache;
	}
};

//--------------------------------------------------------------------------
// CScriptDictionary implementation

CScriptDictionary *CScriptDictionary::Create(asIScriptEngine *engine)
{
	// Use the custom memory routine from AngelScript to allow application to better control how much memory is used
	CScriptDictionary *obj = (CScriptDictionary*)asAllocMem(sizeof(CScriptDictionary));
	new(obj) CScriptDictionary(engine);
	return obj;
}

CScriptDictionary *CScriptDictionary::Create(asBYTE *buffer)
{
	// Use the custom memory routine from AngelScript to allow application to better control how much memory is used
	CScriptDictionary *obj = (CScriptDictionary*)asAllocMem(sizeof(CScriptDictionary));
	new(obj) CScriptDictionary(buffer);
	return obj;
}

CScriptDictionary::CScriptDictionary(asIScriptEngine *engine)
{
	Init(engine);
}

void CScriptDictionary::Init(asIScriptEngine *e)
{
	// We start with one reference
	refCount = 1;
	gcFlag = false;
	iterGuard = 0;

	// Keep a reference to the engine for as long as we live
	// We don't increment the reference counter, because the
	// engine will hold a pointer to the object in the GC.
	engine = e;

	// The dictionary object type is cached to avoid dynamically parsing it each time
	SDictionaryCache *cache = reinterpret_cast<SDictionaryCache*>(engine->GetUserData(DICTIONARY_CACHE));

	// Notify the garbage collector of this object
	engine->NotifyGarbageCollectorOfNewObject(this, cache->dictType);
}

CScriptDictionary::CScriptDictionary(asBYTE *buffer)
{
	// This constructor will always be called from a script
	// so we can get the engine from the active context
	asIScriptContext *ctx = asGetActiveContext();
	Init(ctx->GetEngine());

	// Determine if the dictionary key type is registered as reference type or value type
	SDictionaryCache& cache = *reinterpret_cast<SDictionaryCache*>(engine->GetUserData(DICTIONARY_CACHE));
	bool keyAsRef = cache.keyType->GetFlags() & asOBJ_REF ? true : false;

	// Initialize the dictionary from the buffer
	asUINT length = *(asUINT*)buffer;
	buffer += 4;

	while( length-- )
	{
		// Align the buffer pointer on a 4 byte boundary in
		// case previous value was smaller than 4 bytes
		if( asPWORD(buffer) & 0x3 )
			buffer += 4 - (asPWORD(buffer) & 0x3);

		// Get the name value pair from the buffer and insert it in the dictionary
		dictKey_t name;
		if (keyAsRef)
		{
			name = **(dictKey_t**)buffer;
			buffer += sizeof(dictKey_t*);
		}
		else
		{
			name = *(dictKey_t*)buffer;
			buffer += sizeof(dictKey_t);
		}

		// Get the type id of the value
		int typeId = *(int*)buffer;
		buffer += sizeof(int);

		// Depending on the type id, the value will inline in the buffer or a pointer
		void *ref = (void*)buffer;

		if( typeId >= asTYPEID_INT8 && typeId <= asTYPEID_DOUBLE )
		{
			// Convert primitive values to either int64 or double, so we can use the overloaded Set methods
			asINT64 i64;
			double d;
			switch( typeId )
			{
			case asTYPEID_INT8:   i64 = *(char*)          ref; break;
			case asTYPEID_INT16:  i64 = *(short*)         ref; break;
			case asTYPEID_INT32:  i64 = *(int*)           ref; break;
			case asTYPEID_INT64:  i64 = *(asINT64*)       ref; break;
			case asTYPEID_UINT8:  i64 = *(unsigned char*) ref; break;
			case asTYPEID_UINT16: i64 = *(unsigned short*)ref; break;
			case asTYPEID_UINT32: i64 = *(unsigned int*)  ref; break;
			case asTYPEID_UINT64: i64 = *(asINT64*)       ref; break;
			case asTYPEID_FLOAT:  d   = *(float*)         ref; break;
			case asTYPEID_DOUBLE: d   = *(double*)        ref; break;
			}

			if( typeId >= asTYPEID_FLOAT )
				Set(name, d);
			else
				Set(name, i64);
		}
		else
		{
			if( (typeId & asTYPEID_MASK_OBJECT) &&
				!(typeId & asTYPEID_OBJHANDLE) &&
				(engine->GetTypeInfoById(typeId)->GetFlags() & asOBJ_REF) )
			{
				// Dereference the pointer to get the reference to the actual object
				ref = *(void**)ref;
			}

			Set(name, ref, typeId);
		}

		// Advance the buffer pointer with the size of the value
		if( typeId & asTYPEID_MASK_OBJECT )
		{
			asITypeInfo *ti = engine->GetTypeInfoById(typeId);
			if( ti->GetFlags() & asOBJ_VALUE )
				buffer += ti->GetSize();
			else
				buffer += sizeof(void*);
		}
		else if( typeId == 0 )
		{
			// null pointer
			buffer += sizeof(void*);
		}
		else
		{
			buffer += engine->GetSizeOfPrimitiveType(typeId);
		}
	}
}

CScriptDictionary::~CScriptDictionary()
{
	// Delete all keys and values
	DeleteAll();
}

void CScriptDictionary::AddRef() const
{
	// We need to clear the GC flag
	gcFlag = false;
	asAtomicInc(refCount);
}

void CScriptDictionary::Release() const
{
	// We need to clear the GC flag
	gcFlag = false;
	if( asAtomicDec(refCount) == 0 )
	{
		this->~CScriptDictionary();
		asFreeMem(const_cast<CScriptDictionary*>(this));
	}
}

int CScriptDictionary::GetRefCount()
{
	return refCount;
}

void CScriptDictionary::SetGCFlag()
{
	gcFlag = true;
}

bool CScriptDictionary::GetGCFlag()
{
	return gcFlag;
}

void CScriptDictionary::EnumReferences(asIScriptEngine *inEngine)
{
	// The collector may run on another thread than the one using this dictionary, see StructureLock
	std::lock_guard<std::mutex> guard(StructureLock(this));

	// Call the gc enum callback for each of the objects
	dictMap_t::iterator it;
	for( it = dict.begin(); it != dict.end(); it++ )
	{
		// ALTERED: only entries that hold an object, as CScriptAny::EnumReferences does. An entry without one (a null handle,
		// or a value whose copy failed) holds no reference, and nothing keeps its type alive: when the type was a class of a
		// script module that has been discarded since (a script_module's discard(), or the main module at exit while the
		// dictionary lives on), GetTypeInfoById returned null and reading its flags crashed the collector.
		// ALTERED: the value and its type are read under the value's lock, see ValueLock
		std::lock_guard<std::recursive_mutex> valueGuard(ValueLock(&it->second));
		if (it->second.m_valueObj && (it->second.m_typeId & asTYPEID_MASK_OBJECT))
		{
			asITypeInfo *subType = engine->GetTypeInfoById(it->second.m_typeId);
			if ((subType->GetFlags() & asOBJ_VALUE) && (subType->GetFlags() & asOBJ_GC))
			{
				// For value types we need to forward the enum callback
				// to the object so it can decide what to do
				engine->ForwardGCEnumReferences(it->second.m_valueObj, subType);
			}
			else
			{
				// For others, simply notify the GC about the reference
				inEngine->GCEnumCallback(it->second.m_valueObj);
			}
		}
	}
}

void CScriptDictionary::ReleaseAllReferences(asIScriptEngine * /*engine*/)
{
	// We're being told to release all references in
	// order to break circular references for dead objects
	DeleteAll();
}

CScriptDictionary &CScriptDictionary::operator =(const CScriptDictionary &other)
{
	// ALTERED: both dictionaries are held, and the keys of the other are copied from a list taken first, each value looked up
	// again when its turn comes. The copies of the values are script code (see Set), which can let go of either dictionary or
	// change the other, whose walk went on through freed nodes.
	SDictionaryHold holdThis(this), holdOther(&other);

	// ALTERED: assigning a dictionary to itself (d = d) emptied it, as everything was deleted before being copied from
	// itself. It is left as it is, as the array add-on does.
	if( &other == this )
		return *this;

	// Clear everything we had before
	DeleteAll();

	// Do a shallow copy of the dictionary
	std::vector<dictKey_t> keys;
	keys.reserve(other.dict.size());
	dictMap_t::const_iterator it;
	for( it = other.dict.begin(); it != other.dict.end(); it++ )
		keys.push_back(it->first);
	for( size_t n = 0; n < keys.size(); n++ )
	{
		it = other.dict.find(keys[n]);
		if( it == other.dict.end() )
			continue;
		if( it->second.m_typeId & asTYPEID_OBJHANDLE )
			Set(keys[n], (void*)const_cast<void**>(&it->second.m_valueObj), it->second.m_typeId);
		else if( it->second.m_typeId & asTYPEID_MASK_OBJECT )
			Set(keys[n], (void*)it->second.m_valueObj, it->second.m_typeId);
		else
			Set(keys[n], (void*)const_cast<asINT64*>(&it->second.m_valueInt), it->second.m_typeId);
	}

	return *this;
}

CScriptDictValue *CScriptDictionary::operator[](const dictKey_t &key)
{
	// Return the existing value if it exists, else insert an empty value
	dictMap_t::iterator it = dict.find(key);
	if( it == dict.end() )
	{
		std::lock_guard<std::mutex> guard(StructureLock(this));
		it = dict.insert(dictMap_t::value_type(key, CScriptDictValue())).first;
	}
	CScriptDictValue &val = it->second;
	
	// Ensure the dictionary value has the engine pointer set (it will be null if newly created in above operation)
	if (val.m_engine == 0)
	{
		val.m_engine = engine;
		iterGuard++;
	}

	return &val;
}

const CScriptDictValue *CScriptDictionary::operator[](const dictKey_t &key) const
{
	// Return the existing value if it exists
	dictMap_t::const_iterator it;
	it = dict.find(key);
	if( it != dict.end() )
		return &it->second;

	// Else raise an exception
	asIScriptContext *ctx = asGetActiveContext();
	if( ctx )
		ctx->SetException("Invalid access to non-existing value");

	return 0;
}

void CScriptDictionary::Set(const dictKey_t &key, void *value, int typeId)
{
	// ALTERED: the new value is made first, with the dictionary held, then put under the key, and the value it replaces is
	// released last (by made's destructor). The copy of an object is script code (a copy constructor, opAssign), which can let
	// go of the dictionary or delete the key: it ran on the key's value in the dictionary, which was then written to after it
	// had been freed. The key is now added after the copy.
	// The key is copied first when the copy can run script code, which could change or free the string it refers to (an
	// element of an array it empties).
	SDictionaryHold hold(this);
	dictKey_t keyCopy;
	const dictKey_t *k = &key;
	if( (typeId & asTYPEID_MASK_OBJECT) && !(typeId & asTYPEID_OBJHANDLE) )
	{
		keyCopy = key;
		k = &keyCopy;
	}
	CScriptDictValue made(engine, value, typeId);

	dictMap_t::iterator it;
	it = dict.find(*k);
	if (it == dict.end())
	{
		std::lock_guard<std::mutex> guard(StructureLock(this));
		it = dict.insert(dictMap_t::value_type(*k, CScriptDictValue(engine))).first;
		iterGuard++;
	}

	// The value and its type are swapped under the dictionary's lock: the collector, which can run on another thread (see
	// StructureLock), reads both under it, and between the two writes it found the new value under the old type or the
	// old value under the new one (an integer taken for an object, or an object enumerated as another type).
	std::lock_guard<std::mutex> guard(StructureLock(this));
	asINT64 v = it->second.m_valueInt;
	int t = it->second.m_typeId;
	it->second.m_valueInt = made.m_valueInt;
	it->second.m_typeId = made.m_typeId;
	made.m_valueInt = v;
	made.m_typeId = t;
}

// This overloaded method is implemented so that all integer and
// unsigned integers types will be stored in the dictionary as int64
// through implicit conversions. This simplifies the management of the
// numeric types when the script retrieves the stored value using a
// different type.
void CScriptDictionary::Set(const dictKey_t &key, const asINT64 &value)
{
	Set(key, const_cast<asINT64*>(&value), asTYPEID_INT64);
}

// This overloaded method is implemented so that all floating point types
// will be stored in the dictionary as double through implicit conversions.
// This simplifies the management of the numeric types when the script
// retrieves the stored value using a different type.
void CScriptDictionary::Set(const dictKey_t &key, const double &value)
{
	Set(key, const_cast<double*>(&value), asTYPEID_DOUBLE);
}

// Returns true if the value was successfully retrieved
bool CScriptDictionary::Get(const dictKey_t &key, void *value, int typeId) const
{
	dictMap_t::const_iterator it;
	it = dict.find(key);
	if( it != dict.end() && it->second.Get(value, typeId) )
		return true;

	// The ?&out temporary that AngelScript hands us for primitives and handles is NOT initialized, and it is copied back
	// into the caller's variable whatever we return. Left untouched it delivers stack garbage (or whatever the previous
	// call left there) to scripts that test the return value only afterwards, so give them a deterministic zero/null.
	if( typeId & asTYPEID_OBJHANDLE )
		*reinterpret_cast<void**>(value) = 0;
	else if( !(typeId & asTYPEID_MASK_OBJECT) )
	{
		int size = engine->GetSizeOfPrimitiveType(typeId);
		if( size > 0 ) memset(value, 0, size);
	}
	return false;
}

// Returns the type id of the stored value
int CScriptDictionary::GetTypeId(const dictKey_t &key) const
{
	dictMap_t::const_iterator it;
	it = dict.find(key);
	if( it != dict.end() )
		return it->second.m_typeId;

	return -1;
}

bool CScriptDictionary::Get(const dictKey_t &key, asINT64 &value) const
{
	return Get(key, &value, asTYPEID_INT64);
}

bool CScriptDictionary::Get(const dictKey_t &key, double &value) const
{
	return Get(key, &value, asTYPEID_DOUBLE);
}

bool CScriptDictionary::Exists(const dictKey_t &key) const
{
	dictMap_t::const_iterator it;
	it = dict.find(key);
	if( it != dict.end() )
		return true;

	return false;
}

bool CScriptDictionary::IsEmpty() const
{
	if( dict.size() == 0 )
		return true;

	return false;
}

asUINT CScriptDictionary::GetSize() const
{
	return asUINT(dict.size());
}

bool CScriptDictionary::Delete(const dictKey_t &key)
{
	dictMap_t::iterator it;
	it = dict.find(key);
	if( it != dict.end() )
	{
		// ALTERED: the value is taken out of the dictionary and released after the key is gone (by removed's destructor).
		// Releasing it can run a destructor (script code), which ran while the key was still there and could delete it again
		// or let go of the dictionary, and the erase then used a freed node.
		CScriptDictValue removed(engine);
		{
			// ALTERED: the entry is emptied under the dictionary's lock too, as the collector reads it under that lock
			std::lock_guard<std::mutex> guard(StructureLock(this));
			removed.m_valueInt = it->second.m_valueInt;
			removed.m_typeId = it->second.m_typeId;
			it->second.m_valueObj = 0;
			it->second.m_typeId = 0;
			dict.erase(it);
		}
		iterGuard++;
		return true;
	}

	return false;
}

void CScriptDictionary::DeleteAll()
{
	// ALTERED: the values are taken out of the dictionary and released after it is empty (by removed's destructor). Releasing
	// them can run destructors (script code), which ran during the walk of the dictionary and could delete keys from it, add
	// to it or let go of it, and the walk went on through freed nodes.
	dictMap_t removed;
	{
		std::lock_guard<std::mutex> guard(StructureLock(this));
		removed.swap(dict);
	}
	iterGuard++;
}

CScriptArray* CScriptDictionary::GetKeys() const
{
	// Retrieve the object type for the array<string> from the cache
	SDictionaryCache *cache = reinterpret_cast<SDictionaryCache*>(engine->GetUserData(DICTIONARY_CACHE));
	asITypeInfo *ti = cache->arrayType;

	// Create the array object
	CScriptArray *array = CScriptArray::Create(ti, asUINT(dict.size()));
	long current = -1;
	dictMap_t::const_iterator it;
	for( it = dict.begin(); it != dict.end(); it++ )
	{
		current++;
		*(dictKey_t*)array->At(current) = it->first;
	}

	return array;
}

//--------------------------------------------------------------------------
// Generic wrappers

void ScriptDictionaryFactory_Generic(asIScriptGeneric *gen)
{
	*(CScriptDictionary**)gen->GetAddressOfReturnLocation() = CScriptDictionary::Create(gen->GetEngine());
}

void ScriptDictionaryListFactory_Generic(asIScriptGeneric *gen)
{
	asBYTE *buffer = (asBYTE*)gen->GetArgAddress(0);
	*(CScriptDictionary**)gen->GetAddressOfReturnLocation() = CScriptDictionary::Create(buffer);
}

void ScriptDictionaryAddRef_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dict->AddRef();
}

void ScriptDictionaryRelease_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dict->Release();
}

void ScriptDictionaryAssign_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	CScriptDictionary *other = *(CScriptDictionary**)gen->GetAddressOfArg(0);
	*dict = *other;
	*(CScriptDictionary**)gen->GetAddressOfReturnLocation() = dict;
}

void ScriptDictionarySet_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	void *ref = *(void**)gen->GetAddressOfArg(1);
	int typeId = gen->GetArgTypeId(1);
	dict->Set(*key, ref, typeId);
}

void ScriptDictionarySetInt_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	void *ref = *(void**)gen->GetAddressOfArg(1);
	dict->Set(*key, *(asINT64*)ref);
}

void ScriptDictionarySetFlt_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	void *ref = *(void**)gen->GetAddressOfArg(1);
	dict->Set(*key, *(double*)ref);
}

void ScriptDictionaryGet_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	void *ref = *(void**)gen->GetAddressOfArg(1);
	int typeId = gen->GetArgTypeId(1);
	*(bool*)gen->GetAddressOfReturnLocation() = dict->Get(*key, ref, typeId);
}

void ScriptDictionaryGetInt_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	void *ref = *(void**)gen->GetAddressOfArg(1);
	*(bool*)gen->GetAddressOfReturnLocation() = dict->Get(*key, *(asINT64*)ref);
}

void ScriptDictionaryGetFlt_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	void *ref = *(void**)gen->GetAddressOfArg(1);
	*(bool*)gen->GetAddressOfReturnLocation() = dict->Get(*key, *(double*)ref);
}

void ScriptDictionaryExists_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	bool ret = dict->Exists(*key);
	*(bool*)gen->GetAddressOfReturnLocation() = ret;
}

void ScriptDictionaryIsEmpty_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	bool ret = dict->IsEmpty();
	*(bool*)gen->GetAddressOfReturnLocation() = ret;
}

void ScriptDictionaryGetSize_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	asUINT ret = dict->GetSize();
	*(asUINT*)gen->GetAddressOfReturnLocation() = ret;
}

void ScriptDictionaryDelete_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	*(bool*)gen->GetAddressOfReturnLocation() = dict->Delete(*key);
}

void ScriptDictionaryDeleteAll_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *dict = (CScriptDictionary*)gen->GetObject();
	dict->DeleteAll();
}

static void ScriptDictionaryGetRefCount_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *self = (CScriptDictionary*)gen->GetObject();
	*(int*)gen->GetAddressOfReturnLocation() = self->GetRefCount();
}

static void ScriptDictionarySetGCFlag_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *self = (CScriptDictionary*)gen->GetObject();
	self->SetGCFlag();
}

static void ScriptDictionaryGetGCFlag_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *self = (CScriptDictionary*)gen->GetObject();
	*(bool*)gen->GetAddressOfReturnLocation() = self->GetGCFlag();
}

static void ScriptDictionaryEnumReferences_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *self = (CScriptDictionary*)gen->GetObject();
	asIScriptEngine *engine = *(asIScriptEngine**)gen->GetAddressOfArg(0);
	self->EnumReferences(engine);
}

static void ScriptDictionaryReleaseAllReferences_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *self = (CScriptDictionary*)gen->GetObject();
	asIScriptEngine *engine = *(asIScriptEngine**)gen->GetAddressOfArg(0);
	self->ReleaseAllReferences(engine);
}

static void CScriptDictionaryGetKeys_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *self = (CScriptDictionary*)gen->GetObject();
	*(CScriptArray**)gen->GetAddressOfReturnLocation() = self->GetKeys();
}

static void CScriptDictionary_opIndex_Generic(asIScriptGeneric *gen)
{
	CScriptDictionary *self = (CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	*(CScriptDictValue**)gen->GetAddressOfReturnLocation() = self->operator[](*key);
}

static void CScriptDictionary_opIndex_const_Generic(asIScriptGeneric *gen)
{
	const CScriptDictionary *self = (const CScriptDictionary*)gen->GetObject();
	dictKey_t *key = *(dictKey_t**)gen->GetAddressOfArg(0);
	*(const CScriptDictValue**)gen->GetAddressOfReturnLocation() = self->operator[](*key);
}


//-------------------------------------------------------------------------
// CScriptDictValue

CScriptDictValue::CScriptDictValue(asIScriptEngine *engine, void *value, int typeId)
{
	m_valueObj = 0;
	m_typeId   = 0;

	// Don't increase the reference count, since the engine anyway holds a pointer to the owning dictionary in the GC
	// TODO: If the dictionaryValue is used as a standalone object, then it may be necessary to increase refcount in the engine
	m_engine   = engine;

	Set(value, typeId);
}

CScriptDictValue::~CScriptDictValue()
{
	FreeValue();
}

void CScriptDictValue::FreeValue()
{
	// If it is a handle or a ref counted object, call release
	if( m_typeId & asTYPEID_MASK_OBJECT )
	{
		// ALTERED: the value is emptied before the object is released, not after: a destructor run by the release that set or
		// cleared this same value (a dictionaryValue, or one the garbage collector releases) released the object a second time
		// ALTERED: under the value's lock, as the collector can be reading it on another thread, see ValueLock
		void *obj;
		int typeId;
		{
			std::lock_guard<std::recursive_mutex> guard(ValueLock(this));
			obj = m_valueObj;
			typeId = m_typeId;
			m_valueObj = 0;
			m_typeId = 0;
		}

		// Let the engine release the object
		m_engine->ReleaseScriptObject(obj, m_engine->GetTypeInfoById(typeId));
	}

	// For primitives, there's nothing to do
}


void CScriptDictValue::ReleaseReferences(asIScriptEngine*)
{
	FreeValue();
}

void CScriptDictValue::EnumReferences(asIScriptEngine *inEngine)
{
	assert(inEngine == m_engine);

	// ALTERED: the value and its type are read under the value's lock, see ValueLock
	std::lock_guard<std::recursive_mutex> guard(ValueLock(this));

	// If we're holding a reference, we'll notify the garbage collector of it
	if (m_valueObj)
		inEngine->GCEnumCallback(m_valueObj);

	// The object type itself is also garbage collected
	if (m_typeId)
		inEngine->GCEnumCallback(inEngine->GetTypeInfoById(m_typeId));
}

void CScriptDictValue::Set(void *value, int typeId)
{
	// ALTERED: the new value is made before the old one is released, and the old one is released last (by made's destructor,
	// as made holds it after the swap below). The old one was released first, which destroyed the value being assigned when it
	// was this very value: d['k'] = d['k'] copied a freed object (a string, or a script class stored by value). The object
	// being copied is held for its copy, see SDictObjectHold.
	CScriptDictValue made(m_engine);
	made.m_typeId = typeId;
	if( typeId & asTYPEID_OBJHANDLE )
	{
		// We're receiving a reference to the handle, so we need to dereference it
		made.m_valueObj = *(void**)value;
		m_engine->AddRefScriptObject(made.m_valueObj, m_engine->GetTypeInfoById(typeId));
	}
	else if( typeId & asTYPEID_MASK_OBJECT )
	{
		// Create a copy of the object
		SDictObjectHold hold(m_engine, value, typeId);
		made.m_valueObj = m_engine->CreateScriptObjectCopy(value, m_engine->GetTypeInfoById(typeId));
		if( made.m_valueObj == 0 )
		{
			// ALTERED: not over an exception the copy raised itself (a script class's copy constructor), whose text and line
			// the engine forwards; that one says why
			asIScriptContext *ctx = asGetActiveContext();
			if( ctx && ctx->GetState() != asEXECUTION_EXCEPTION )
				ctx->SetException("Cannot create copy of object");
		}
	}
	else
	{
		// Copy the primitive value
		// We receive a pointer to the value.
		int size = m_engine->GetSizeOfPrimitiveType(typeId);
		memcpy(&made.m_valueInt, value, size);
	}

	// ALTERED: swapped under the value's lock, as the collector can be reading it on another thread, see ValueLock (the value
	// replaced is released after the lock, by made's destructor)
	std::lock_guard<std::recursive_mutex> guard(ValueLock(this));
	asINT64 v = m_valueInt;
	int t = m_typeId;
	m_valueInt = made.m_valueInt;
	m_typeId = made.m_typeId;
	made.m_valueInt = v;
	made.m_typeId = t;
}

void CScriptDictValue::Set(CScriptDictValue &value)
{
	assert(m_engine == value.m_engine);
	if( value.m_typeId & asTYPEID_OBJHANDLE )
		Set((void*)&value.m_valueObj, value.m_typeId);
	else if( value.m_typeId & asTYPEID_MASK_OBJECT )
		Set((void*)value.m_valueObj, value.m_typeId);
	else
		Set((void*)&value.m_valueInt, value.m_typeId);
}

// This overloaded method is implemented so that all integer and
// unsigned integers types will be stored in the dictionary as int64
// through implicit conversions. This simplifies the management of the
// numeric types when the script retrieves the stored value using a
// different type.
void CScriptDictValue::Set(const asINT64 &value)
{
	Set(const_cast<asINT64*>(&value), asTYPEID_INT64);
}

// This overloaded method is implemented so that all floating point types
// will be stored in the dictionary as double through implicit conversions.
// This simplifies the management of the numeric types when the script
// retrieves the stored value using a different type.
void CScriptDictValue::Set(const double &value)
{
	Set(const_cast<double*>(&value), asTYPEID_DOUBLE);
}

bool CScriptDictValue::Get(void *value, int typeId) const
{
	// Return the value
	if( typeId & asTYPEID_OBJHANDLE )
	{
		// A handle can be retrieved if the stored type is a handle of same or compatible type
		// or if the stored type is an object that implements the interface that the handle refer to.
		if( (m_typeId & asTYPEID_MASK_OBJECT) )
		{
			// Don't allow the get if the stored handle is to a const, but the desired handle is not
			if( (m_typeId & asTYPEID_HANDLETOCONST) && !(typeId & asTYPEID_HANDLETOCONST) )
				return false;

			// RefCastObject will increment the refcount if successful
			SDictObjectHold hold(m_engine, m_valueObj, m_typeId); // ALTERED: a cast can be script code, see SDictObjectHold
			m_engine->RefCastObject(m_valueObj, m_engine->GetTypeInfoById(m_typeId), m_engine->GetTypeInfoById(typeId), reinterpret_cast<void**>(value));

			return true;
		}
	}
	else if( typeId & asTYPEID_MASK_OBJECT )
	{
		// Verify that the copy can be made
		bool isCompatible = false;

		// Allow a handle to be value assigned if the wanted type is not a handle
		if( (m_typeId & ~(asTYPEID_OBJHANDLE | asTYPEID_HANDLETOCONST) ) == typeId && m_valueObj != 0 )
			isCompatible = true;

		// Copy the object into the given reference
		if( isCompatible )
		{
			SDictObjectHold hold(m_engine, m_valueObj, m_typeId); // ALTERED: opAssign is script code, see SDictObjectHold
			m_engine->AssignScriptObject(value, m_valueObj, m_engine->GetTypeInfoById(typeId));

			return true;
		}
	}
	else
	{
		if( m_typeId == typeId )
		{
			int size = m_engine->GetSizeOfPrimitiveType(typeId);
			memcpy(value, &m_valueInt, size);
			return true;
		}

		// We know all numbers are stored as either int64 or double, since we register overloaded functions for those
		// Only bool and enums needs to be treated separately
		if( typeId == asTYPEID_DOUBLE )
		{
			if( m_typeId == asTYPEID_INT64 )
				*(double*)value = double(m_valueInt);
			else if (m_typeId == asTYPEID_BOOL)
			{
				// Use memcpy instead of type cast to make sure the code is endianess agnostic
				char localValue;
				memcpy(&localValue, &m_valueInt, sizeof(char));
				*(double*)value = localValue ? 1.0 : 0.0;
			}
			else if (m_typeId > asTYPEID_DOUBLE && (m_typeId & asTYPEID_MASK_OBJECT) == 0)
				*(double*)value = double(EnumToInt64(m_engine, m_typeId, &m_valueInt)); // ALTERED: see EnumToInt64
			else
			{
				// The stored type is an object
				// TODO: Check if the object has a conversion operator to a primitive value
				*(double*)value = 0;
				return false;
			}
			return true;
		}
		else if( typeId == asTYPEID_INT64 )
		{
			if( m_typeId == asTYPEID_DOUBLE )
				*(asINT64*)value = asINT64(m_valueFlt);
			else if (m_typeId == asTYPEID_BOOL)
			{
				// Use memcpy instead of type cast to make sure the code is endianess agnostic
				char localValue;
				memcpy(&localValue, &m_valueInt, sizeof(char));
				*(asINT64*)value = localValue ? 1 : 0;
			}
			else if (m_typeId > asTYPEID_DOUBLE && (m_typeId & asTYPEID_MASK_OBJECT) == 0)
				*(asINT64*)value = EnumToInt64(m_engine, m_typeId, &m_valueInt); // ALTERED: see EnumToInt64
			else
			{
				// The stored type is an object
				// TODO: Check if the object has a conversion operator to a primitive value
				*(asINT64*)value = 0;
				return false;
			}
			return true;
		}
		else if( typeId > asTYPEID_DOUBLE && (m_typeId & asTYPEID_MASK_OBJECT) == 0 )
		{
			// The desired type is an enum
			// ALTERED: of its underlying type's size, see EnumToInt64
			if( m_typeId == asTYPEID_DOUBLE )
				Int64ToEnum(m_engine, typeId, asINT64(m_valueFlt), value);
			else if( m_typeId == asTYPEID_INT64 )
				Int64ToEnum(m_engine, typeId, m_valueInt, value);
			else if (m_typeId == asTYPEID_BOOL)
			{
				// Use memcpy instead of type cast to make sure the code is endianess agnostic
				char localValue;
				memcpy(&localValue, &m_valueInt, sizeof(char));
				Int64ToEnum(m_engine, typeId, localValue ? 1 : 0, value);
			}
			else if (m_typeId > asTYPEID_DOUBLE && (m_typeId & asTYPEID_MASK_OBJECT) == 0)
				Int64ToEnum(m_engine, typeId, EnumToInt64(m_engine, m_typeId, &m_valueInt), value);
			else
			{
				// The stored type is an object
				// TODO: Check if the object has a conversion operator to a primitive value
				Int64ToEnum(m_engine, typeId, 0, value);
				return false;
			}
			return true;
		}
		else if( typeId == asTYPEID_BOOL )
		{
			if (m_typeId & asTYPEID_OBJHANDLE)
			{
				// TODO: Check if the object has a conversion operator to a primitive value
				*(bool*)value = m_valueObj ? true : false;
			}
			else if( m_typeId & asTYPEID_MASK_OBJECT )
			{
				// TODO: Check if the object has a conversion operator to a primitive value
				*(bool*)value = true;
			}
			else
			{
				// Compare only the bytes that were actually set
				asQWORD zero = 0;
				int size = m_engine->GetSizeOfPrimitiveType(m_typeId);
				*(bool*)value = memcmp(&m_valueInt, &zero, size) == 0 ? false : true;
			}
			return true;
		}
	}

	// It was not possible to retrieve the value using the desired typeId
	return false;
}

const void * CScriptDictValue::GetAddressOfValue() const
{
	if( (m_typeId & asTYPEID_MASK_OBJECT) && !(m_typeId & asTYPEID_OBJHANDLE) )
	{
		// Return the address to the object directly
		return m_valueObj;
	}

	// Return the address of the primitive or the pointer to the object
	return reinterpret_cast<const void*>(&m_valueObj);
}

bool CScriptDictValue::Get(asINT64 &value) const
{
	return Get(&value, asTYPEID_INT64);
}

bool CScriptDictValue::Get(double &value) const
{
	return Get(&value, asTYPEID_DOUBLE);
}

int CScriptDictValue::GetTypeId() const
{
	return m_typeId;
}

static void CScriptDictValue_Destruct(CScriptDictValue *obj)
{
	obj->~CScriptDictValue();
}

static CScriptDictValue &CScriptDictValue_opAssign(void *ref, int typeId, CScriptDictValue *obj)
{
	obj->Set(ref, typeId);
	return *obj;
}

static CScriptDictValue &CScriptDictValue_opAssign(const CScriptDictValue &other, CScriptDictValue *obj)
{
	obj->Set(const_cast<CScriptDictValue&>(other));
	return *obj;
}

static CScriptDictValue &CScriptDictValue_opAssign(double val, CScriptDictValue *obj)
{
	return CScriptDictValue_opAssign(&val, asTYPEID_DOUBLE, obj);
}

static CScriptDictValue &CScriptDictValue_opAssign(asINT64 val, CScriptDictValue *obj)
{
	return CScriptDictValue_opAssign(&val, asTYPEID_INT64, obj);
}

static void CScriptDictValue_opCast(void *ref, int typeId, CScriptDictValue *obj)
{
	obj->Get(ref, typeId);
}

static asINT64 CScriptDictValue_opConvInt(CScriptDictValue *obj)
{
	asINT64 value;
	CScriptDictValue_opCast(&value, asTYPEID_INT64, obj);
	return value;
}

static double CScriptDictValue_opConvDouble(CScriptDictValue *obj)
{
	double value;
	CScriptDictValue_opCast(&value, asTYPEID_DOUBLE, obj);
	return value;
}

//-------------------------------------------------------------------
// generic wrapper for CScriptDictValue

static void CScriptDictValue_opConvDouble_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	double value;
	self->Get(value);
	*(double*)gen->GetAddressOfReturnLocation() = value;
}

static void CScriptDictValue_opConvInt_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	asINT64 value;
	self->Get(value);
	*(asINT64*)gen->GetAddressOfReturnLocation() = value;
}

static void CScriptDictValue_opCast_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	self->Get(gen->GetArgAddress(0), gen->GetArgTypeId(0));
}

static void CScriptDictValue_opAssign_int64_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	*(CScriptDictValue**)gen->GetAddressOfReturnLocation() = &CScriptDictValue_opAssign((asINT64)gen->GetArgQWord(0), self);
}

static void CScriptDictValue_opAssign_double_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	*(CScriptDictValue**)gen->GetAddressOfReturnLocation() = &CScriptDictValue_opAssign(gen->GetArgDouble(0), self);
}

static void CScriptDictValue_opAssign_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	*(CScriptDictValue**)gen->GetAddressOfReturnLocation() = &CScriptDictValue_opAssign(gen->GetArgAddress(0), gen->GetArgTypeId(0), self);
}

static void CScriptDictValue_opCopyAssign_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	*(CScriptDictValue**)gen->GetAddressOfReturnLocation() = &CScriptDictValue_opAssign(*reinterpret_cast<CScriptDictValue*>(gen->GetArgAddress(0)), self);
}

static void CScriptDictValue_Construct_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	new(self) CScriptDictValue(gen->GetEngine());
}

static void CScriptDictValue_Destruct_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	CScriptDictValue_Destruct(self);
}

static void CScriptDictValue_EnumReferences_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	self->EnumReferences(gen->GetEngine());
}

static void CScriptDictValue_ReleaseReferences_Generic(asIScriptGeneric *gen)
{
	CScriptDictValue *self = (CScriptDictValue*)gen->GetObject();
	self->ReleaseReferences(gen->GetEngine());
}

//----------------------------------------------------------------------------
// Foreach support
// ALTERED: an iterator holds its dictionary (released after the iterator is freed), so that the dictionary it is checked against
// can't be freed and another made in its place while the script still holds the iterator; the guard is 64-bit, so that it doesn't
// come round to an earlier value.
CScriptDictionary::CScriptDictIter::CScriptDictIter(const CScriptDictionary* dict) : iter(dict->begin()), refCount(1), iterGuard(dict->iterGuard), owner(dict) { dict->AddRef(); }
CScriptDictionary::CScriptDictIter::~CScriptDictIter() {}

void CScriptDictionary::CScriptDictIter::AddRef() const
{
	asAtomicInc(refCount);
}

void CScriptDictionary::CScriptDictIter::Release() const
{
	if (asAtomicDec(refCount) == 0)
	{
		const CScriptDictionary* dict = owner;
		this->~CScriptDictIter();
		asFreeMem(const_cast<CScriptDictIter*>(this));
		dict->Release();
	}
}

CScriptDictionary::CScriptDictIter* CScriptDictionary::opForBegin() const
{
	// Use the custom memory routine from AngelScript to allow application to better control how much memory is used
	CScriptDictionary::CScriptDictIter* iter = (CScriptDictionary::CScriptDictIter*)asAllocMem(sizeof(CScriptDictionary::CScriptDictIter));
	new(iter) CScriptDictionary::CScriptDictIter(this);
	return iter;
}

// ALTERED: the iterator is taken by handle (as the script declares it) and checked before it is used. A script can call these methods
// itself, with null, an iterator at its end, one of another dictionary or one whose dictionary changed since; and in foreach, script
// code run by the copy of the value (a copy constructor) can change the dictionary before the key is read. A null iterator was a
// null reference, and reading or advancing an iterator in any of the other cases used a freed node or a map's end.
static void SetDictIterException(const char *message)
{
	asIScriptContext *ctx = asGetActiveContext();
	if( ctx )
		ctx->SetException(message);
}

bool CScriptDictionary::CheckIter(const CScriptDictionary::CScriptDictIter *iter) const
{
	if( iter == 0 )
	{
		SetDictIterException("Null pointer access");
		return false;
	}
	if( iter->owner != this )
	{
		SetDictIterException("The iterator is another dictionary's");
		return false;
	}
	if( iter->iterGuard != iterGuard )
	{
		SetDictIterException("The dictionary was changed during its iteration");
		return false;
	}
	if( iter->iter == end() )
	{
		SetDictIterException("The dictionary iterator is past its end");
		return false;
	}
	return true;
}

bool CScriptDictionary::opForEnd(const CScriptDictionary::CScriptDictIter *iter) const
{
	if( iter == 0 )
	{
		SetDictIterException("Null pointer access");
		return true;
	}

	if (iter->owner != this || iter->iterGuard != iterGuard)
		return true;

	if (iter->iter == end())
		return true;

	return false;
}

CScriptDictionary::CScriptDictIter* CScriptDictionary::opForNext(CScriptDictionary::CScriptDictIter *iter) const
{
	if( iter == 0 )
	{
		SetDictIterException("Null pointer access");
		return 0;
	}

	// An iterator of another dictionary, or of a dictionary that changed (its guard never matches again), stays as it is; it was set
	// to the end by an assignment CIterator doesn't do (its operator= is empty), and advanced past the end
	if (iter->owner == this && iter->iterGuard == iterGuard && iter->iter != end())
		++iter->iter;
	return iter;
}

const CScriptDictValue& CScriptDictionary::opForValue0(const CScriptDictionary::CScriptDictIter *iter) const
{
	static const CScriptDictValue empty;
	if( !CheckIter(iter) )
		return empty;
	return iter->iter.m_it->second;
}

const dictKey_t& CScriptDictionary::opForValue1(const CScriptDictionary::CScriptDictIter *iter) const
{
	static const dictKey_t empty;
	if( !CheckIter(iter) )
		return empty;
	return iter->iter.m_it->first;
}

void ScriptDictIterAddRef_Generic(asIScriptGeneric* gen)
{
	CScriptDictionary::CScriptDictIter* iter = (CScriptDictionary::CScriptDictIter*)gen->GetObject();
	iter->AddRef();
}

void ScriptDictIterRelease_Generic(asIScriptGeneric* gen)
{
	CScriptDictionary::CScriptDictIter* iter = (CScriptDictionary::CScriptDictIter*)gen->GetObject();
	iter->Release();
}

void ScriptDictionary_opForBegin_Generic(asIScriptGeneric* gen)
{
	CScriptDictionary* dict = (CScriptDictionary*)gen->GetObject();
	*(CScriptDictionary::CScriptDictIter**)gen->GetAddressOfReturnLocation() = dict->opForBegin();
}

void ScriptDictionary_opForEnd_Generic(asIScriptGeneric* gen)
{
	CScriptDictionary* dict = (CScriptDictionary*)gen->GetObject();
	CScriptDictionary::CScriptDictIter* iter = *(CScriptDictionary::CScriptDictIter**)gen->GetAddressOfArg(0);
	*(bool*)gen->GetAddressOfReturnLocation() = dict->opForEnd(iter);
}

void ScriptDictionary_opForNext_Generic(asIScriptGeneric* gen)
{
	CScriptDictionary* dict = (CScriptDictionary*)gen->GetObject();
	CScriptDictionary::CScriptDictIter* iter = *(CScriptDictionary::CScriptDictIter**)gen->GetAddressOfArg(0);
	*(CScriptDictionary::CScriptDictIter**)gen->GetAddressOfReturnLocation() = dict->opForNext(iter);
}

void ScriptDictionary_opForValue0_Generic(asIScriptGeneric* gen)
{
	CScriptDictionary* dict = (CScriptDictionary*)gen->GetObject();
	CScriptDictionary::CScriptDictIter* iter = *(CScriptDictionary::CScriptDictIter**)gen->GetAddressOfArg(0);
	*reinterpret_cast<const CScriptDictValue**>(gen->GetAddressOfReturnLocation()) = &dict->opForValue0(iter);
}

void ScriptDictionary_opForValue1_Generic(asIScriptGeneric* gen)
{
	CScriptDictionary* dict = (CScriptDictionary*)gen->GetObject();
	CScriptDictionary::CScriptDictIter* iter = *(CScriptDictionary::CScriptDictIter**)gen->GetAddressOfArg(0);
	*reinterpret_cast<const dictKey_t**>(gen->GetAddressOfReturnLocation()) = &dict->opForValue1(iter);
}

//------------------------------------------------------------------
// Iterator implementation

CScriptDictionary::CIterator CScriptDictionary::begin() const
{
	return CIterator(*this, dict.begin());
}

CScriptDictionary::CIterator CScriptDictionary::end() const
{
	return CIterator(*this, dict.end());
}

CScriptDictionary::CIterator CScriptDictionary::find(const dictKey_t& key) const
{
	return CIterator(*this, dict.find(key));
}

CScriptDictionary::CIterator::CIterator(
	const CScriptDictionary& dict,
	dictMap_t::const_iterator it)
	: m_it(it), m_dict(dict)
{
}

void CScriptDictionary::CIterator::operator++()
{
	++m_it;
}

void CScriptDictionary::CIterator::operator++(int)
{
	++m_it;

	// Normally the post increment would return a copy of the object with the original state,
	// but it is rarely used so we skip this extra copy to avoid unnecessary overhead
}

CScriptDictionary::CIterator& CScriptDictionary::CIterator::operator*()
{
	return *this;
}

bool CScriptDictionary::CIterator::operator==(const CIterator& other) const
{
	return m_it == other.m_it;
}

bool CScriptDictionary::CIterator::operator!=(const CIterator& other) const
{
	return m_it != other.m_it;
}

const dictKey_t& CScriptDictionary::CIterator::GetKey() const
{
	return m_it->first;
}

int CScriptDictionary::CIterator::GetTypeId() const
{
	return m_it->second.m_typeId;
}

bool CScriptDictionary::CIterator::GetValue(asINT64& value) const
{
	return m_it->second.Get(&value, asTYPEID_INT64);
}

bool CScriptDictionary::CIterator::GetValue(double& value) const
{
	return m_it->second.Get(&value, asTYPEID_DOUBLE);
}

bool CScriptDictionary::CIterator::GetValue(void* value, int typeId) const
{
	return m_it->second.Get(value, typeId);
}

const void* CScriptDictionary::CIterator::GetAddressOfValue() const
{
	return m_it->second.GetAddressOfValue();
}

//--------------------------------------------------------------------------
// Register the type

void RegisterScriptDictionary(asIScriptEngine *engine)
{
	if( strstr(asGetLibraryOptions(), "AS_MAX_PORTABILITY") )
		RegisterScriptDictionary_Generic(engine);
	else
		RegisterScriptDictionary_Native(engine);
}

void RegisterScriptDictionary_Native(asIScriptEngine *engine)
{
	int r;

	// The array<string> type must be available
	assert( engine->GetTypeInfoByDecl("array<string>") );

#if AS_CAN_USE_CPP11
	// With C++11 it is possible to use asGetTypeTraits to automatically determine the correct flags that represents the C++ class
	r = engine->RegisterObjectType("dictionaryValue", sizeof(CScriptDictValue), asOBJ_VALUE | asOBJ_ASHANDLE | asOBJ_GC | asGetTypeTraits<CScriptDictValue>()); assert( r >= 0 );
#else
	r = engine->RegisterObjectType("dictionaryValue", sizeof(CScriptDictValue), asOBJ_VALUE | asOBJ_ASHANDLE | asOBJ_GC | asOBJ_APP_CLASS_CD); assert( r >= 0 );
#endif
	r = engine->RegisterObjectBehaviour("dictionaryValue", asBEHAVE_CONSTRUCT, "void f()", asFUNCTION(CScriptDictValue_Construct_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("dictionaryValue", asBEHAVE_DESTRUCT, "void f()", asFUNCTION(CScriptDictValue_Destruct), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionaryValue", asBEHAVE_ENUMREFS, "void f(int&in)", asMETHOD(CScriptDictValue, EnumReferences), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("dictionaryValue", asBEHAVE_RELEASEREFS, "void f(int&in)", asMETHOD(CScriptDictValue, ReleaseReferences), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opAssign(const dictionaryValue &in other)", asFUNCTIONPR(CScriptDictValue_opAssign, (const CScriptDictValue &, CScriptDictValue *), CScriptDictValue &), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opHndlAssign(const ?&in value)", asFUNCTIONPR(CScriptDictValue_opAssign, (void *, int, CScriptDictValue*), CScriptDictValue &), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opHndlAssign(const dictionaryValue &in other)", asFUNCTIONPR(CScriptDictValue_opAssign, (const CScriptDictValue &, CScriptDictValue *), CScriptDictValue &), asCALL_CDECL_OBJLAST); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opAssign(const ?&in value)", asFUNCTIONPR(CScriptDictValue_opAssign, (void *, int, CScriptDictValue*), CScriptDictValue &), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opAssign(double value)", asFUNCTIONPR(CScriptDictValue_opAssign, (double, CScriptDictValue*), CScriptDictValue &), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opAssign(int64 value)", asFUNCTIONPR(CScriptDictValue_opAssign, (asINT64, CScriptDictValue*), CScriptDictValue &), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "void opCast(?&out value)", asFUNCTIONPR(CScriptDictValue_opCast, (void *, int, CScriptDictValue*), void), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "void opConv(?&out value)", asFUNCTIONPR(CScriptDictValue_opCast, (void *, int, CScriptDictValue*), void), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "int64 opConv()", asFUNCTIONPR(CScriptDictValue_opConvInt, (CScriptDictValue*), asINT64), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "double opConv()", asFUNCTIONPR(CScriptDictValue_opConvDouble, (CScriptDictValue*), double), asCALL_CDECL_OBJLAST); assert( r >= 0 );

	r = engine->RegisterObjectType("dictionary", sizeof(CScriptDictionary), asOBJ_REF | asOBJ_GC); assert( r >= 0 );
	// Use the generic interface to construct the object since we need the engine pointer, we could also have retrieved the engine pointer from the active context
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_FACTORY, "dictionary@ f()", asFUNCTION(ScriptDictionaryFactory_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_LIST_FACTORY, "dictionary @f(int &in) {repeat {string, ?}}", asFUNCTION(ScriptDictionaryListFactory_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_ADDREF, "void f()", asMETHOD(CScriptDictionary,AddRef), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_RELEASE, "void f()", asMETHOD(CScriptDictionary,Release), asCALL_THISCALL); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "dictionary &opAssign(const dictionary &in other)", asMETHODPR(CScriptDictionary, operator=, (const CScriptDictionary &), CScriptDictionary&), asCALL_THISCALL); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "void set(const string &in key, const ?&in value)", asMETHODPR(CScriptDictionary,Set,(const dictKey_t&,void*,int),void), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool get(const string &in key, ?&out value) const", asMETHODPR(CScriptDictionary,Get,(const dictKey_t&,void*,int) const,bool), asCALL_THISCALL); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "void set(const string &in key, const int64&in value)", asMETHODPR(CScriptDictionary,Set,(const dictKey_t&,const asINT64&),void), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool get(const string &in key, int64&out value) const", asMETHODPR(CScriptDictionary,Get,(const dictKey_t&,asINT64&) const,bool), asCALL_THISCALL); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "void set(const string &in key, const double&in value)", asMETHODPR(CScriptDictionary,Set,(const dictKey_t&,const double&),void), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool get(const string &in key, double&out value) const", asMETHODPR(CScriptDictionary,Get,(const dictKey_t&,double&) const,bool), asCALL_THISCALL); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "bool exists(const string &in key) const", asMETHOD(CScriptDictionary,Exists), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool is_empty() const", asMETHOD(CScriptDictionary, IsEmpty), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "uint get_size() const", asMETHOD(CScriptDictionary, GetSize), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool delete(const string &in key)", asMETHOD(CScriptDictionary,Delete), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "void delete_all()", asMETHOD(CScriptDictionary,DeleteAll), asCALL_THISCALL); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "array<string> @get_keys() const", asMETHOD(CScriptDictionary,GetKeys), asCALL_THISCALL); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "dictionaryValue &opIndex(const string &in key)", asMETHODPR(CScriptDictionary, operator[], (const dictKey_t &), CScriptDictValue*), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "const dictionaryValue &opIndex(const string &in key) const", asMETHODPR(CScriptDictionary, operator[], (const dictKey_t &) const, const CScriptDictValue*), asCALL_THISCALL); assert( r >= 0 );

	// Register GC behaviours
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_GETREFCOUNT, "int f()", asMETHOD(CScriptDictionary,GetRefCount), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_SETGCFLAG, "void f()", asMETHOD(CScriptDictionary,SetGCFlag), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_GETGCFLAG, "bool f()", asMETHOD(CScriptDictionary,GetGCFlag), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_ENUMREFS, "void f(int&in)", asMETHOD(CScriptDictionary,EnumReferences), asCALL_THISCALL); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_RELEASEREFS, "void f(int&in)", asMETHOD(CScriptDictionary,ReleaseAllReferences), asCALL_THISCALL); assert( r >= 0 );

	// Support foreach
	r = engine->RegisterObjectType("dictionaryIter", 0, asOBJ_REF); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("dictionaryIter", asBEHAVE_ADDREF, "void f()", asMETHOD(CScriptDictionary::CScriptDictIter, AddRef), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("dictionaryIter", asBEHAVE_RELEASE, "void f()", asMETHOD(CScriptDictionary::CScriptDictIter, Release), asCALL_THISCALL); assert(r >= 0);

	r = engine->RegisterObjectMethod("dictionary", "dictionaryIter @opForBegin() const", asMETHODPR(CScriptDictionary, opForBegin, () const, CScriptDictionary::CScriptDictIter *), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionary", "bool opForEnd(dictionaryIter @+ iter) const", asMETHODPR(CScriptDictionary, opForEnd, (const CScriptDictionary::CScriptDictIter*) const, bool), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionary", "dictionaryIter @+ opForNext(dictionaryIter @+ iter) const", asMETHODPR(CScriptDictionary, opForNext, (CScriptDictionary::CScriptDictIter*) const, CScriptDictionary::CScriptDictIter*), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionary", "const dictionaryValue &opForValue0(dictionaryIter @+ iter) const", asMETHODPR(CScriptDictionary, opForValue0, (const CScriptDictionary::CScriptDictIter*) const, const CScriptDictValue &), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionary", "const string &opForValue1(dictionaryIter @+ iter) const", asMETHODPR(CScriptDictionary, opForValue1, (const CScriptDictionary::CScriptDictIter*) const, const dictKey_t&), asCALL_THISCALL); assert(r >= 0);



#if AS_USE_STLNAMES == 1
	// Same as isEmpty
	r = engine->RegisterObjectMethod("dictionary", "bool empty() const", asMETHOD(CScriptDictionary, IsEmpty), asCALL_THISCALL); assert( r >= 0 );
	// Same as getSize
	r = engine->RegisterObjectMethod("dictionary", "uint size() const", asMETHOD(CScriptDictionary, GetSize), asCALL_THISCALL); assert( r >= 0 );
	// Same as delete
	r = engine->RegisterObjectMethod("dictionary", "void erase(const string &in key)", asMETHOD(CScriptDictionary,Delete), asCALL_THISCALL); assert( r >= 0 );
	// Same as deleteAll
	r = engine->RegisterObjectMethod("dictionary", "void clear()", asMETHOD(CScriptDictionary,DeleteAll), asCALL_THISCALL); assert( r >= 0 );
#endif

	// Cache some things the dictionary will need at runtime
	SDictionaryCache::Setup(engine);
}

void RegisterScriptDictionary_Generic(asIScriptEngine *engine)
{
	int r;

	// Register the cleanup callback for the object type cache
	engine->SetEngineUserDataCleanupCallback(SDictionaryCache::Cleanup, DICTIONARY_CACHE);

#if AS_CAN_USE_CPP11
	// With C++11 it is possible to use asGetTypeTraits to automatically determine the correct flags that represents the C++ class
	r = engine->RegisterObjectType("dictionaryValue", sizeof(CScriptDictValue), asOBJ_VALUE | asOBJ_ASHANDLE | asOBJ_GC | asGetTypeTraits<CScriptDictValue>()); assert( r >= 0 );
#else
	r = engine->RegisterObjectType("dictionaryValue", sizeof(CScriptDictValue), asOBJ_VALUE | asOBJ_ASHANDLE | asOBJ_GC | asOBJ_APP_CLASS_CD); assert( r >= 0 );
#endif
	r = engine->RegisterObjectBehaviour("dictionaryValue", asBEHAVE_CONSTRUCT, "void f()", asFUNCTION(CScriptDictValue_Construct_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionaryValue", asBEHAVE_DESTRUCT, "void f()", asFUNCTION(CScriptDictValue_Destruct_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionaryValue", asBEHAVE_ENUMREFS, "void f(int&in)", asFUNCTION(CScriptDictValue_EnumReferences_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("dictionaryValue", asBEHAVE_RELEASEREFS, "void f(int&in)", asFUNCTION(CScriptDictValue_ReleaseReferences_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opAssign(const dictionaryValue &in other)", asFUNCTION(CScriptDictValue_opCopyAssign_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opHndlAssign(const ?&in value)", asFUNCTION(CScriptDictValue_opAssign_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opHndlAssign(const dictionaryValue &in other)", asFUNCTION(CScriptDictValue_opCopyAssign_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opAssign(const ?&in value)", asFUNCTION(CScriptDictValue_opAssign_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opAssign(double value)", asFUNCTION(CScriptDictValue_opAssign_double_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "dictionaryValue &opAssign(int64 value)", asFUNCTION(CScriptDictValue_opAssign_int64_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "void opCast(?&out value)", asFUNCTION(CScriptDictValue_opCast_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "void opConv(?&out value)", asFUNCTION(CScriptDictValue_opCast_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "int64 opConv()", asFUNCTION(CScriptDictValue_opConvInt_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionaryValue", "double opConv()", asFUNCTION(CScriptDictValue_opConvDouble_Generic), asCALL_GENERIC); assert( r >= 0 );

	r = engine->RegisterObjectType("dictionary", sizeof(CScriptDictionary), asOBJ_REF | asOBJ_GC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_FACTORY, "dictionary@ f()", asFUNCTION(ScriptDictionaryFactory_Generic), asCALL_GENERIC); assert( r>= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_LIST_FACTORY, "dictionary @f(int &in) {repeat {string, ?}}", asFUNCTION(ScriptDictionaryListFactory_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_ADDREF, "void f()", asFUNCTION(ScriptDictionaryAddRef_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_RELEASE, "void f()", asFUNCTION(ScriptDictionaryRelease_Generic), asCALL_GENERIC); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "dictionary &opAssign(const dictionary &in other)", asFUNCTION(ScriptDictionaryAssign_Generic), asCALL_GENERIC); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "void set(const string &in key, const ?&in value)", asFUNCTION(ScriptDictionarySet_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool get(const string &in key, ?&out value) const", asFUNCTION(ScriptDictionaryGet_Generic), asCALL_GENERIC); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "void set(const string &in key, const int64&in value)", asFUNCTION(ScriptDictionarySetInt_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool get(const string &in key, int64&out value) const", asFUNCTION(ScriptDictionaryGetInt_Generic), asCALL_GENERIC); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "void set(const string &in key, const double&in value)", asFUNCTION(ScriptDictionarySetFlt_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool get(const string &in key, double&out value) const", asFUNCTION(ScriptDictionaryGetFlt_Generic), asCALL_GENERIC); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "bool exists(const string &in key) const", asFUNCTION(ScriptDictionaryExists_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool is_empty() const", asFUNCTION(ScriptDictionaryIsEmpty_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "uint get_size() const", asFUNCTION(ScriptDictionaryGetSize_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "bool delete(const string &in key)", asFUNCTION(ScriptDictionaryDelete_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "void delete_all()", asFUNCTION(ScriptDictionaryDeleteAll_Generic), asCALL_GENERIC); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "array<string> @get_keys() const", asFUNCTION(CScriptDictionaryGetKeys_Generic), asCALL_GENERIC); assert( r >= 0 );

	r = engine->RegisterObjectMethod("dictionary", "dictionaryValue &opIndex(const string &in key)", asFUNCTION(CScriptDictionary_opIndex_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectMethod("dictionary", "const dictionaryValue &opIndex(const string &in key) const", asFUNCTION(CScriptDictionary_opIndex_const_Generic), asCALL_GENERIC); assert( r >= 0 );

	// Register GC behaviours
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_GETREFCOUNT, "int f()", asFUNCTION(ScriptDictionaryGetRefCount_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_SETGCFLAG, "void f()", asFUNCTION(ScriptDictionarySetGCFlag_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_GETGCFLAG, "bool f()", asFUNCTION(ScriptDictionaryGetGCFlag_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_ENUMREFS, "void f(int&in)", asFUNCTION(ScriptDictionaryEnumReferences_Generic), asCALL_GENERIC); assert( r >= 0 );
	r = engine->RegisterObjectBehaviour("dictionary", asBEHAVE_RELEASEREFS, "void f(int&in)", asFUNCTION(ScriptDictionaryReleaseAllReferences_Generic), asCALL_GENERIC); assert( r >= 0 );

	// Support foreach
	r = engine->RegisterObjectType("dictionaryIter", 0, asOBJ_REF); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("dictionaryIter", asBEHAVE_ADDREF, "void f()", asFUNCTION(ScriptDictIterAddRef_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("dictionaryIter", asBEHAVE_RELEASE, "void f()", asFUNCTION(ScriptDictIterRelease_Generic), asCALL_GENERIC); assert(r >= 0);

	r = engine->RegisterObjectMethod("dictionary", "dictionaryIter @opForBegin() const", asFUNCTION(ScriptDictionary_opForBegin_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionary", "bool opForEnd(dictionaryIter @+ iter) const", asFUNCTION(ScriptDictionary_opForEnd_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionary", "dictionaryIter @+ opForNext(dictionaryIter @+ iter) const", asFUNCTION(ScriptDictionary_opForNext_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionary", "const dictionaryValue &opForValue0(dictionaryIter @+ iter) const", asFUNCTION(ScriptDictionary_opForValue0_Generic), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectMethod("dictionary", "const string &opForValue1(dictionaryIter @+ iter) const", asFUNCTION(ScriptDictionary_opForValue1_Generic), asCALL_GENERIC); assert(r >= 0);

	// Cache some things the dictionary will need at runtime
	SDictionaryCache::Setup(engine);
}

END_AS_NAMESPACE


