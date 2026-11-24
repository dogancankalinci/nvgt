// All functions other than string.split and join were written by Sam Tupy for NVGT and fall under that project's zlib license.

#include <assert.h>
#include "scriptstdstring.h"
#include "scriptarray.h"
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <vector>
using namespace std;

BEGIN_AS_NAMESPACE

static asITypeInfo *StringArrayType = NULL;
// ALTERED: an array that couldn't be made or grown, for want of memory or as too large (the array add-on raised the exception), ends the
// split with that exception: the parts were written through the null pointer the array gives for an element it doesn't have, a crash.
static CScriptArray *SplitFailed(CScriptArray *array)
{
	if (array)
		array->Release();
	return 0;
}
// This function takes an input string and splits it into parts by looking
// for a specified delimiter. Example:
//
// string str = "A|B||D";
// array<string>@ array = str.split("|");
//
// The resulting array has the following elements:
//
// {"A", "B", "", "D"}
//
// AngelScript signature:
// array<string>@ string::split(const string &in delim, bool full = true) const
static CScriptArray *StringRSplit(const string &delim, bool full, bool allow_blanks, asUINT max_elements, const string &str, CScriptArray *array)
{
	// Splits from the right like python's str.rsplit, collecting pieces last to first so that at most max_elements are produced and the first one is the unsplit remainder.
	vector<string> parts;
	size_t end = str.size(), dl = full ? delim.size() : 1;
	while (parts.size() + 1 < max_elements && end >= dl)
	{
		size_t pos = full ? str.rfind(delim, end - dl) : str.find_last_of(delim, end - 1);
		if (pos == string::npos) break;
		if (allow_blanks || end - pos - dl > 0) parts.push_back(str.substr(pos + dl, end - pos - dl));
		end = pos;
	}
	if (!allow_blanks) // Skip any delimiters left dangling at the end of the remainder.
		while (end >= dl && (full ? str.compare(end - dl, dl, delim) == 0 : delim.find(str[end - 1]) != string::npos)) end -= dl;
	if (allow_blanks || end > 0 || parts.empty()) parts.push_back(str.substr(0, end));
	array->Resize(parts.size());
	// An element the engine had no memory for is left null with the exception raised, at the size asked for, see StringSplit.
	asIScriptContext *ctx = asGetActiveContext();
	if (array->GetSize() != parts.size() || (ctx && ctx->GetState() == asEXECUTION_EXCEPTION))
		return SplitFailed(array); // see SplitFailed
	for (size_t i = 0; i < parts.size(); i++) *(string *)array->At(parts.size() - 1 - i) = std::move(parts[i]);
	return array;
}

// If max_elements is greater than 0, at most that many elements are returned, the last one being the unsplit remainder of the string. If it is less than 0 the same applies counting from the right, like python's str.rsplit.
static CScriptArray *StringSplit(const string &delim, bool full, bool allow_blanks, int max_elements, const string &str)
{
	// Obtain a pointer to the engine
	asIScriptContext *ctx = asGetActiveContext();
	asIScriptEngine *engine = ctx->GetEngine();

	// TODO: This assumes that CScriptArray was already registered
	if (!StringArrayType)
		StringArrayType = engine->GetTypeInfoByDecl("array<string>");

	// Create the array object
	CScriptArray *array = CScriptArray::Create(StringArrayType);
	if (!array)
		return 0; // see SplitFailed
	// The array add-on raised an exception (see SplitFailed): for want of memory, a Reserve() leaves the array as it was.
	auto raised = [ctx]() { return ctx->GetState() == asEXECUTION_EXCEPTION; };

	// Fix: Previously a 1-length array was always returned from an empty string.
	if (!allow_blanks && str == "") return array; // Nothing to split.

	if (delim == "")
	{
		array->InsertLast((void *)&str);
		if (array->GetSize() != 1 || raised())
			return SplitFailed(array);
		return array;
	}
	if (max_elements < 0) return StringRSplit(delim, full, allow_blanks, (asUINT)-(long long)max_elements, str, array);
	asUINT reserved = str.size() * 0.05; // Sam: Not sure how to predict how many elements we should initially reserve as each string could be different. Does it matter?
	array->Reserve(reserved);
	if (raised())
		return SplitFailed(array);

	// Find the existence of the delimiter in the input string
	size_t pos = 0, prev = 0;
	asUINT count = 0;
	while ((max_elements <= 0 || array->GetSize() + 1 < (asUINT)max_elements) && (pos = (full ? str.find(delim, prev) : str.find_first_of(delim, prev))) != string::npos)
	{
		if (count > reserved)
		{
			// ALTERED: grown without wrapping round, which made it smaller than the parts already there
			reserved = reserved > 0xFFFFFFFFu / 8 ? 0xFFFFFFFFu : reserved * 8;
			array->Reserve(reserved);
			if (raised())
				return SplitFailed(array);
		}
		// Add the part to the array
		if (allow_blanks || pos - prev > 0)
		{
			array->Resize(array->GetSize() + 1);
			// The new element is null when the engine had no memory for the string (the exception is raised, the size is the
			// one asked for), and the part was assigned through it.
			if (array->GetSize() != count + 1 || raised())
				return SplitFailed(array);
			((string *)array->At(count))->assign(&str[prev], pos - prev);
			count++;
		}
		// Find the next part
		if (full)
			prev = pos + delim.length();
		else
		{
			// One character of the set was matched, so step over exactly that character. Walking on while further
			// delimiters follow collapsed a run of them into one and swallowed the empty parts between them even when
			// the caller had asked for blanks, and it measured that run against the size of the delimiter set, which is
			// a count of accepted characters rather than a length in the text.
			prev = pos + 1;
		}
	}

	if (!allow_blanks && max_elements > 0) // The loop may have stopped early, so skip delimiters at the start of the unsplit remainder.
		while (prev < str.size() && (full ? str.compare(prev, delim.size(), delim) == 0 : delim.find(str[prev]) != string::npos)) prev += full ? delim.size() : 1;
	// Add the remaining part if needed. A string ending on a delimiter leaves an empty part behind it, which counts
	// when blanks were asked for; dropping it silently lost the last field of text like "a,b,".
	if (array->GetSize() < 1 || str.size() - prev > 0 || allow_blanks)
	{
		array->Resize(array->GetSize() + 1);
		if (array->GetSize() != count + 1 || raised()) // as above
			return SplitFailed(array);
		((string *)array->At(count))->assign(&str[prev], str.size() - prev);
	}
	array->Resize(array->GetSize());
	return array;
}

static void StringSplit_Generic(asIScriptGeneric *gen)
{
	// Get the arguments
	string *str = (string *)gen->GetObject();
	string *delim = *(string **)gen->GetAddressOfArg(0);
	bool full = gen->GetArgByte(1);
	bool allow_blanks = gen->GetArgByte(2);
	int max_elements = gen->GetArgDWord(3);

	// Return the array by handle
	*(CScriptArray **)gen->GetAddressOfReturnLocation() = StringSplit(*delim, full, allow_blanks, max_elements, *str);
}

// This function takes as input an array of string handles as well as a
// delimiter and concatenates the array elements into one delimited string.
// Example:
//
// array<string> array = {"A", "B", "", "D"};
// string str = join(array, "|");
//
// The resulting string is:
//
// "A|B||D"
//
// AngelScript signature:
// string join(const array<string> &in array, const string &in delim)
static string StringJoin(const CScriptArray &array, const string &delim, int start, int count)
{
	// Create the new string
	string str = "";
	int size = array.GetSize();
	if (start < 0 || start >= size) return "";
	if (count < -1 || count == 0) return "";
	// ALTERED: a count reaching past the end is measured against what is left, not added to start: start + count overflowed (undefined) for a
	// count near INT_MAX, and gcc's code then joined elements past the end of the array (join(a, ",", 1, 2147483647) read beyond it).
	int end = (count == -1 || count >= size - start) ? size : start + count;
	int n = start;
	for (n = start; n < end - 1; n++)
	{
		str += *(string *)array.At(n);
		str += delim;
	}

		// Add the last part
	str += *(string *)array.At(n);

	return str;
}

static void StringJoin_Generic(asIScriptGeneric *gen)
{
	// Get the arguments
	CScriptArray *array = *(CScriptArray **)gen->GetAddressOfArg(0);
	string *delim = *(string **)gen->GetAddressOfArg(1);
	int start = *(int *)gen->GetAddressOfArg(2);
	int count = *(int *)gen->GetAddressOfArg(3);

	// Return the string
	new (gen->GetAddressOfReturnLocation()) string(StringJoin(*array, *delim, start, count));
}
// As an alternativve to string::substr, this function returns a substring of the input string by emulating Python's string slicing, or at least a convenient subset of it.
// The only slight oddity is that since angelscript doesn't support blank arguments in cases such as str[5:] or str[:-4], we use the number 0 to indicate such slices.
// "hello".slice(0, 2) returns "he"
// "hello".slice(0, 0) returns "hello" because in angelscript we cannot emulate "hello"[0:]
// "hello".slice(-3, 0) returns "llo" because in angelscript we cannot emulate "hello"[-3:]
//
// AngelScript signature:
// string string::slice(int start = 0, int end = 0) const
static string StringSlice(int start, int end, const string &str)
{
	// ALTERED: resolved in 64 bits. As ints, end - start overflowed (undefined) for bounds near INT_MIN and INT_MAX, and the size of a
	// string of 2 GB or more didn't fit.
	long long size = (long long)str.size(), s = start, e = end;
	if (s < 0)
		s += size;
	if (e <= 0)
		e += size;
	if (e > size)
		e = size;
	if (s < 0 || s >= size || e <= s)
		return "";
	return str.substr((size_t)s, (size_t)(e - s));
}

// This function replaces a range of bytes(start, count) with a string of text.
//
// AngelScript signature:
// string string::replaceRange(uint start, int count, string& replace) const
static string StringReplaceRange(asUINT start, int count, const string &replace, const string &str)
{
	if (start >= str.size() || count < 1)
		return str;
	// A count that reaches past the end has to take only what is left, otherwise append is asked for a position beyond
	// the string and throws, so replacing the rest of a string without measuring it first failed here while the same
	// call on replace_range_this worked, std::string::replace having clamped it.
	size_t removed = static_cast<size_t>(count) < str.size() - start ? static_cast<size_t>(count) : str.size() - start;
	// Recreate the string so that the original stays in tact.
	string ret(&str[0], start);
	ret += replace;
	ret.append(str, start + removed, str.size() - (start + removed));
	return ret;
}

// Like replace_range, but modifies the string in place instead of returning a new one.
//
// AngelScript signature:
// string& string::replace_range_this(uint start, int count, const string &in replace)
static string &StringReplaceRangeThis(asUINT start, int count, const string &replace, string &str)
{
	if (start >= str.size() || count < 1)
		return str;
	str.replace(start, (size_t)count, replace);
	return str;
}

// This function replaces a given substring of text with another.
// Set replaceAll to false to only replace the first occurrence of the text.
//
// AngelScript signature:
// string string::replace(string& search, string& replace) const
static string StringReplace(const string &search, const string &replace, bool replaceAll, asUINT offset, const string &str)
{
	if (search == "" || str == "")
		return str;
	// ALTERED: the result is built as the matches are found. Each replacement made in place of a match of another length moved the whole
	// rest of the string, so the time grew with the square of the matches: a 2 MB string with a million matches took 21 seconds (14 ms
	// now). The matches are the same: each search goes on after the last match, as it went on after the replacement put in its place.
	size_t pos = str.find(search, offset);
	if (pos == string::npos)
		return str;
	string ret;
	ret.reserve(str.size());
	size_t last = 0;
	do
	{
		ret.append(str, last, pos - last);
		ret += replace;
		last = pos + search.length();
		if (!replaceAll)
			break;
		pos = str.find(search, last);
	} while (pos != string::npos);
	ret.append(str, last, string::npos);
	return ret;
}
// Like above, but does so in place.
static string &StringReplaceThis(const string &search, const string &replace, bool replaceAll, asUINT offset, string &str)
{
	// ALTERED: see StringReplace, whose result takes the string's place (search and replace can be the string itself, so it is built apart).
	if (search == "" || str == "" || str.find(search, offset) == string::npos)
		return str;
	string ret = StringReplace(search, replace, replaceAll, offset, str);
	str.swap(ret);
	return str;
}

static void StringSlice_Generic(asIScriptGeneric *gen)
{
	// Get the arguments
	string *str = (string *)gen->GetObject();
	int start = *(int *)gen->GetAddressOfArg(0);
	int end = *(int *)gen->GetAddressOfArg(1);

	// Return the substring
	new (gen->GetAddressOfReturnLocation()) string(StringSlice(start, end, *str));
}

// ALTERED: the arguments are numbered from 0 (the object isn't one), as in the other wrappers here: these two read each from the next
// one's place (the count as the start, the replacement as the count) and the last from past the end. The value returned is made in the
// return location, which holds no string yet, not assigned to it. Only builds with AS_MAX_PORTABILITY use them.
static void StringReplaceRange_Generic(asIScriptGeneric *gen)
{
	asUINT start = gen->GetArgDWord(0);
	int count = gen->GetArgDWord(1);
	string *replace = reinterpret_cast<string *>(gen->GetArgAddress(2));
	string *self = reinterpret_cast<string *>(gen->GetObject());
	new (gen->GetAddressOfReturnLocation()) string(StringReplaceRange(start, count, *replace, *self));
}

static void StringReplaceRangeThis_Generic(asIScriptGeneric *gen)
{
	asUINT start = gen->GetArgDWord(0);
	int count = gen->GetArgDWord(1);
	string *replace = reinterpret_cast<string *>(gen->GetArgAddress(2));
	string *self = reinterpret_cast<string *>(gen->GetObject());
	gen->SetReturnAddress(&StringReplaceRangeThis(start, count, *replace, *self));
}

static void StringReplace_Generic(asIScriptGeneric *gen)
{
	// ALTERED: see StringReplaceRange_Generic
	string *search = reinterpret_cast<string *>(gen->GetArgAddress(0));
	string *replace = reinterpret_cast<string *>(gen->GetArgAddress(1));
	bool replaceAll = gen->GetArgByte(2);
	asUINT offset = gen->GetArgDWord(3);
	string *self = reinterpret_cast<string *>(gen->GetObject());
	new (gen->GetAddressOfReturnLocation()) string(StringReplace(*search, *replace, replaceAll, offset, *self));
}

// Returns a reversed version of the given string.
//
// AngelScript signature:
// string string::reverse() const
static string StringReverse(const string &str)
{
	string ret(&str[0], str.size());
	std::reverse(ret.begin(), ret.end());
	return ret;
}
// Returns a lower case version of the given string.
//
// AngelScript signature:
// string string::lower() const
static string StringLower(const string &str)
{
	string ret;
	ret.reserve(str.size());
	for (size_t i = 0; i < str.size(); i++)
		ret += (char)tolower((unsigned char)str[i]); // <cctype> takes an unsigned char's value: a plain char is negative for a byte of 0x80 or more where char is signed.
	return ret;
}

// Returns an upper case version of the given string.
//
// AngelScript signature:
// string string::lower() const
static string StringUpper(const string &str)
{
	string ret;
	ret.reserve(str.size());
	for (size_t i = 0; i < str.size(); i++)
		ret += (char)toupper((unsigned char)str[i]);
	return ret;
}

// Returns true if this string is lowercase.
//
// AngelScript signature:
// bool string::isLower() const
static bool StringIsLower(const string &str)
{
	for (size_t i = 0; i < str.size(); i++)
	{
		if (!islower((unsigned char)str[i]))
			return false;
	}
	return true;
}

// Returns true if this string is uppercase.
//
// AngelScript signature:
// bool string::isUpper() const
static bool StringIsUpper(const string &str)
{
	for (size_t i = 0; i < str.size(); i++)
	{
		if (!isupper((unsigned char)str[i]))
			return false;
	}
	return true;
}

// Returns true if this string is punctuation.
//
// AngelScript signature:
// bool string::isPunct() const
static bool StringIsPunct(const string &str)
{
	for (size_t i = 0; i < str.size(); i++)
	{
		if (!ispunct((unsigned char)str[i]))
			return false;
	}
	return true;
}

// Returns true if this string is digits.
//
// AngelScript signature:
// bool string::isDigit() const
static bool StringIsDigit(const string &str)
{
	if (str.size() < 1)
		return false;
	for (size_t i = 0; i < str.size(); i++)
	{
		if (!isdigit((unsigned char)str[i]))
			return false;
	}
	return true;
}

// Returns true if this string is alphabetic.
//
// AngelScript signature:
// bool string::isAlpha() const
static bool StringIsAlpha(const string &str)
{
	for (size_t i = 0; i < str.size(); i++)
	{
		if (!isalpha((unsigned char)str[i]))
			return false;
	}
	return true;
}

// Returns true if this string is alphabetic or numeric.
//
// AngelScript signature:
// bool string::isAlphanum() const
static bool StringIsAlphanum(const string &str)
{
	for (size_t i = 0; i < str.size(); i++)
	{
		if (!isalnum((unsigned char)str[i]))
			return false;
	}
	return true;
}

static string string_multiply(const string &str, asUINT multiplier)
{
	if (multiplier == 0)
		return "";
	else if (multiplier == 1)
		return str;
	string result = str;
	result.reserve(str.size() * multiplier);
	for (asUINT i = 0; i < multiplier - 1; i++)
		result += str;
	return result;
}
static string &string_multiply_assign(string &str, asUINT multiplier)
{
	if (multiplier == 0)
	{
		str = "";
		str.shrink_to_fit();
		return str;
	}
	else if (multiplier == 1)
		return str;
	str.reserve(str.size() * multiplier);
	string tmp = str;
	for (asUINT i = 0; i < multiplier - 1; i++)
		str += tmp;
	return str;
}
static asQWORD string_count(string &str, const string &search, asQWORD start)
{
	// ALTERED: a start past the end finds nothing: on 32-bit targets (armeabi-v7a) the uint64 start was cut to size_t for find(), so
	// count("a", 4294967296) counted from 0. The count is 64 bits, as returned (a 32-bit one wrapped for a string of more than 4 GB).
	if (str.empty() || search.empty() || start >= str.size())
		return 0;
	asQWORD c = 0;
	while (true)
	{
		size_t pos = str.find(search, size_t(start));
		if (pos == std::string::npos)
			break;
		start = pos + 1;
		c++;
	}
	return c;
}

// This is where the utility functions are registered.
// The string type must have been registered first.
void RegisterStdStringUtils(asIScriptEngine *engine)
{
	int r;

	if (strstr(asGetLibraryOptions(), "AS_MAX_PORTABILITY"))
	{
		r = engine->RegisterObjectMethod("string", "array<string>@ split(const string &in delimiter, bool full = true, bool allow_blanks = false, int max_elements = 0) const", asFUNCTION(StringSplit_Generic), asCALL_GENERIC);
		assert(r >= 0);
		r = engine->RegisterGlobalFunction("string join(const array<string> &in arr, const string &in delimiter, int start = 0, int count = -1)", asFUNCTION(StringJoin_Generic), asCALL_GENERIC);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string slice(int start = 0, int end = 0) const", asFUNCTION(StringSlice_Generic), asCALL_GENERIC);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string replace_range(uint start, int count, const string& in replacement) const", asFUNCTION(StringReplaceRange_Generic), asCALL_GENERIC);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string& replace_range_this(uint start, int count, const string& in replacement)", asFUNCTION(StringReplaceRangeThis_Generic), asCALL_GENERIC);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string replace(const string& in search, const string& in replacement, bool replace_all = true, uint offset = 0) const", asFUNCTION(StringReplace_Generic), asCALL_GENERIC);
		assert(r >= 0);
	}
	else
	{
		r = engine->RegisterObjectMethod("string", "array<string>@ split(const string &in delimiter, bool full = true, bool allow_blanks = false, int max_elements = 0) const", asFUNCTION(StringSplit), asCALL_CDECL_OBJLAST);
		assert(r >= 0);
		r = engine->RegisterGlobalFunction("string join(const array<string> &in arr, const string &in delimiter, int start = 0, int count = -1)", asFUNCTION(StringJoin), asCALL_CDECL);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string slice(int start = 0, int end = 0) const", asFUNCTION(StringSlice), asCALL_CDECL_OBJLAST);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string replace_range(uint start, int count, const string& in replacement) const", asFUNCTION(StringReplaceRange), asCALL_CDECL_OBJLAST);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string& replace_range_this(uint start, int count, const string& in replacement)", asFUNCTION(StringReplaceRangeThis), asCALL_CDECL_OBJLAST);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string replace(const string& in search, const string& in replacement, bool replace_all = true, uint offset = 0) const", asFUNCTION(StringReplace), asCALL_CDECL_OBJLAST);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string& replace_this(const string& in search, const string& in replacement, bool replace_all = true, uint offset = 0)", asFUNCTION(StringReplaceThis), asCALL_CDECL_OBJLAST);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string reverse_bytes() const", asFUNCTION(StringReverse), asCALL_CDECL_OBJLAST);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string opMul(uint count) const", asFUNCTION(string_multiply), asCALL_CDECL_OBJFIRST);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "string& opMulAssign(uint count)", asFUNCTION(string_multiply_assign), asCALL_CDECL_OBJFIRST);
		assert(r >= 0);
		r = engine->RegisterObjectMethod("string", "uint64 count(const string&in search, uint64 start = 0) const", asFUNCTION(string_count), asCALL_CDECL_OBJFIRST);
		assert(r >= 0);
		// r = engine->RegisterObjectMethod("string", "string lower() const", asFUNCTION(StringLower), asCALL_CDECL_OBJLAST); assert( r >= 0 );
		// r = engine->RegisterObjectMethod("string", "string upper() const", asFUNCTION(StringUpper), asCALL_CDECL_OBJLAST); assert( r >= 0 );
		// r = engine->RegisterObjectMethod("string", "bool is_lower() const", asFUNCTION(StringIsLower), asCALL_CDECL_OBJLAST); assert( r >= 0 );
		// r = engine->RegisterObjectMethod("string", "bool is_upper() const", asFUNCTION(StringIsUpper), asCALL_CDECL_OBJLAST); assert( r >= 0 );
		// r = engine->RegisterObjectMethod("string", "bool is_punctuation() const", asFUNCTION(StringIsPunct), asCALL_CDECL_OBJLAST); assert( r >= 0 );
		// r = engine->RegisterObjectMethod("string", "bool is_alphabetic() const", asFUNCTION(StringIsAlpha), asCALL_CDECL_OBJLAST); assert( r >= 0 );
		// r = engine->RegisterObjectMethod("string", "bool is_digits() const", asFUNCTION(StringIsDigit), asCALL_CDECL_OBJLAST); assert( r >= 0 );
		// r = engine->RegisterObjectMethod("string", "bool is_alphanumeric() const", asFUNCTION(StringIsAlphanum), asCALL_CDECL_OBJLAST); assert( r >= 0 );
	}
}

END_AS_NAMESPACE
