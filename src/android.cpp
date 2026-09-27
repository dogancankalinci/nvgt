/* android.cpp - module containing functions only applicable to the Android platform, usually wrapping java counterparts via JNI
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

#ifdef __ANDROID__
#include "android.h"
#include "UI.h"
#include <jni.h>
#include <time.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <Poco/Exception.h>
#include <Poco/Format.h>
#include <SDL3/SDL.h>
#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <memory>

// Define global error variable so linker can find it
extern int g_LastError;

// A JNIEnv and a local reference belong to the thread that obtained them, and script code runs on any thread,
// so neither is ever kept: every function fetches its own thread's JNIEnv from SDL, which also attaches a thread
// the VM doesn't know yet, and whatever outlives a call is a global reference.
static std::once_flag g_jni_setup_flag;
static jclass TTSClass = nullptr;
static jclass DialogUtilsClass = nullptr;
static jmethodID midIsScreenReaderActive = nullptr;
static jmethodID midScreenReaderDetect = nullptr;
static jmethodID midScreenReaderSpeak = nullptr;
static jmethodID midScreenReaderSilence = nullptr;
static jmethodID midTTSGetEnginePackages = nullptr;
static jmethodID midTTSGetDefaultEnginePackage = nullptr;
static jmethodID midGetExceptionInfo = nullptr;

// Clears the exception a call into Java left pending, printing it to the log, and reports whether there was one.
// While an exception is pending, almost every JNI function is off limits and the VM may abort the process.
static bool jni_clear_exception(JNIEnv* env) {
	if (!env->ExceptionCheck()) return false;
	env->ExceptionDescribe();
	env->ExceptionClear();
	return true;
}

// FindClass searches with the class loader of the Java method that called into native code. On a thread NVGT
// started itself there is no such method, so the VM falls back to the system class loader, which knows only the
// platform's classes; there the class is loaded through the activity's class loader instead.
jclass android_find_app_class(JNIEnv* env, const char* name) {
	jclass cls = env->FindClass(name);
	if (cls) return cls;
	env->ExceptionClear();
	LocalRef<jobject> activity(env, (jobject)SDL_GetAndroidActivity());
	if (!activity.get()) { env->ExceptionClear(); return nullptr; }
	LocalRef<jclass> contextClass(env, env->FindClass("android/content/Context"));
	if (!contextClass.get()) { env->ExceptionClear(); return nullptr; }
	jmethodID midGetClassLoader = env->GetMethodID(contextClass.get(), "getClassLoader", "()Ljava/lang/ClassLoader;");
	if (!midGetClassLoader) { env->ExceptionClear(); return nullptr; }
	LocalRef<jobject> loader(env, env->CallObjectMethod(activity.get(), midGetClassLoader));
	if (env->ExceptionCheck() || !loader.get()) { env->ExceptionClear(); return nullptr; }
	LocalRef<jclass> loaderClass(env, env->FindClass("java/lang/ClassLoader"));
	if (!loaderClass.get()) { env->ExceptionClear(); return nullptr; }
	jmethodID midLoadClass = env->GetMethodID(loaderClass.get(), "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
	if (!midLoadClass) { env->ExceptionClear(); return nullptr; }
	std::string binary_name = name; // loadClass takes a binary name: dots between packages, $ before a nested class.
	std::replace(binary_name.begin(), binary_name.end(), '/', '.');
	LocalRef<jstring> jname(env, env->NewStringUTF(binary_name.c_str()));
	if (!jname.get()) { env->ExceptionClear(); return nullptr; }
	cls = (jclass)env->CallObjectMethod(loader.get(), midLoadClass, jname.get());
	if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
	return cls;
}

// Thread-safe, and all or nothing: nothing is published unless every lookup succeeds, and a failed attempt throws
// without marking the setup done, so the next call tries again.
void android_setup_jni() {
	std::call_once(g_jni_setup_flag, []() {
		JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
		if (!env) throw Poco::Exception("cannot retrieve JNI environment");
		LocalRef<jclass> tts(env, android_find_app_class(env, "com/samtupy/nvgt/TTS"));
		if (!tts.get()) throw Poco::Exception("cannot find TTS class");
		LocalRef<jclass> dialogUtils(env, android_find_app_class(env, "com/samtupy/nvgt/DialogUtils"));
		if (!dialogUtils.get()) throw Poco::Exception("cannot find DialogUtils class");
		auto static_method = [env](jclass cls, const char* name, const char* sig) {
			jmethodID mid = env->GetStaticMethodID(cls, name, sig);
			if (!mid) {
				env->ExceptionClear();
				throw Poco::Exception("cannot find Java method", name);
			}
			return mid;
		};
		jmethodID isScreenReaderActive = static_method(tts, "isScreenReaderActive", "()Z");
		jmethodID screenReaderDetect = static_method(tts, "screenReaderDetect", "()Ljava/lang/String;");
		jmethodID screenReaderSpeak = static_method(tts, "screenReaderSpeak", "(Ljava/lang/String;Z)Z");
		jmethodID screenReaderSilence = static_method(tts, "screenReaderSilence", "()Z");
		jmethodID getEnginePackages = static_method(tts, "getEnginePackages", "()Ljava/util/List;");
		jmethodID getDefaultEnginePackage = static_method(tts, "getDefaultEnginePackage", "()Ljava/lang/String;");
		jmethodID getExceptionInfo = static_method(dialogUtils, "getExceptionInfo", "(Ljava/lang/Throwable;)Ljava/lang/String;");
		jclass ttsGlobal = (jclass)env->NewGlobalRef(tts);
		jclass dialogUtilsGlobal = (jclass)env->NewGlobalRef(dialogUtils);
		if (!ttsGlobal || !dialogUtilsGlobal) {
			if (ttsGlobal) env->DeleteGlobalRef(ttsGlobal);
			if (dialogUtilsGlobal) env->DeleteGlobalRef(dialogUtilsGlobal);
			env->ExceptionClear();
			throw Poco::Exception("cannot create global references to the TTS and DialogUtils classes");
		}
		TTSClass = ttsGlobal;
		DialogUtilsClass = dialogUtilsGlobal;
		midIsScreenReaderActive = isScreenReaderActive;
		midScreenReaderDetect = screenReaderDetect;
		midScreenReaderSpeak = screenReaderSpeak;
		midScreenReaderSilence = screenReaderSilence;
		midTTSGetEnginePackages = getEnginePackages;
		midTTSGetDefaultEnginePackage = getDefaultEnginePackage;
		midGetExceptionInfo = getExceptionInfo;
	});
}

std::string get_java_exception_details(JNIEnv* env, jthrowable ex) {
	try {
		android_setup_jni();
	} catch(...) {
		return "CRITICAL: Unable to setup JNI to print exception.";
	}
	LocalRef<jstring> jdetails(env, (jstring)env->CallStaticObjectMethod(DialogUtilsClass, midGetExceptionInfo, ex));
	if (jni_clear_exception(env)) return "Unknown Java Exception (describing it failed)";
	if (!jdetails.get()) return "Unknown Java Exception (null details)";
	return from_jstring(env, jdetails.get());
}

void check_jni_exception(JNIEnv* env, const std::string& context) {
	if (env->ExceptionCheck()) {
		LocalRef<jthrowable> ex(env, env->ExceptionOccurred());
		env->ExceptionClear();
		std::string details = get_java_exception_details(env, ex.get());
		throw JNIException(Poco::format("JNI exception:\nContext: %s\nException details: %s", context, details));
	}
}

// Java strings are UTF-16. The JNI functions that take or return char* (NewStringUTF, GetStringUTFChars) instead
// speak Java's modified UTF-8, which differs from UTF-8 in ways scripts do run into: a character outside the
// Basic Multilingual Plane, such as an emoji, comes back as two 3-byte surrogate halves that no UTF-8 decoder
// accepts, and NewStringUTF is only defined for valid modified UTF-8, so arbitrary bytes from a script can make a
// VM running CheckJNI abort. Strings are therefore converted here and cross as UTF-16.
static void append_utf8(std::string& out, char32_t c) {
	if (c < 0x80) out += (char)c;
	else if (c < 0x800) {
		out += (char)(0xC0 | (c >> 6));
		out += (char)(0x80 | (c & 0x3F));
	} else if (c < 0x10000) {
		out += (char)(0xE0 | (c >> 12));
		out += (char)(0x80 | ((c >> 6) & 0x3F));
		out += (char)(0x80 | (c & 0x3F));
	} else {
		out += (char)(0xF0 | (c >> 18));
		out += (char)(0x80 | ((c >> 12) & 0x3F));
		out += (char)(0x80 | ((c >> 6) & 0x3F));
		out += (char)(0x80 | (c & 0x3F));
	}
}
// A surrogate half that isn't part of a pair becomes U+FFFD.
static std::string utf16_to_utf8(const char16_t* units, size_t length) {
	std::string out;
	out.reserve(length);
	for (size_t i = 0; i < length; i++) {
		char32_t c = units[i];
		if (c >= 0xD800 && c <= 0xDBFF && i + 1 < length && units[i + 1] >= 0xDC00 && units[i + 1] <= 0xDFFF) {
			c = 0x10000 + ((c - 0xD800) << 10) + (units[i + 1] - 0xDC00);
			i++;
		} else if (c >= 0xD800 && c <= 0xDFFF) c = 0xFFFD;
		append_utf8(out, c);
	}
	return out;
}
// Each malformed sequence (a stray or truncated byte run, an overlong form, an encoded surrogate or a value past
// U+10FFFF) becomes one U+FFFD, and decoding resumes at the first byte that can't belong to it.
static std::u16string utf8_to_utf16(const std::string& str) {
	std::u16string out;
	out.reserve(str.size());
	const unsigned char* s = (const unsigned char*)str.data();
	size_t n = str.size();
	for (size_t i = 0; i < n;) {
		unsigned char lead = s[i];
		char32_t c;
		size_t length;
		if (lead < 0x80) c = lead, length = 1;
		else if (lead >= 0xC2 && lead <= 0xDF) c = lead & 0x1F, length = 2;
		else if (lead >= 0xE0 && lead <= 0xEF) c = lead & 0x0F, length = 3;
		else if (lead >= 0xF0 && lead <= 0xF4) c = lead & 0x07, length = 4;
		else {
			out += u'�';
			i++;
			continue;
		}
		size_t used = 1;
		while (used < length && i + used < n && (s[i + used] & 0xC0) == 0x80) c = (c << 6) | (s[i + used++] & 0x3F);
		i += used;
		if (used < length || (length == 3 && c < 0x800) || (length == 4 && (c < 0x10000 || c > 0x10FFFF)) || (c >= 0xD800 && c <= 0xDFFF)) out += u'�';
		else if (c >= 0x10000) {
			out += (char16_t)(0xD800 + ((c - 0x10000) >> 10));
			out += (char16_t)(0xDC00 + ((c - 0x10000) & 0x3FF));
		} else out += (char16_t)c;
	}
	return out;
}

std::string from_jstring(JNIEnv* env, jstring jstr) {
	if (!jstr) return "";
	jsize length = env->GetStringLength(jstr);
	if (length <= 0) return "";
	std::u16string units(length, u'\0');
	env->GetStringRegion(jstr, 0, length, (jchar*)&units[0]);
	if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
	return utf16_to_utf8(units.data(), units.size());
}

jstring to_jstring(JNIEnv* env, const std::string& str) {
	std::u16string units = utf8_to_utf16(str);
	jstring result = env->NewString((const jchar*)units.data(), (jsize)units.size());
	if (!result) env->ExceptionClear(); // OutOfMemoryError; callers treat a null jstring as a failure.
	return result;
}

// Files added to a build with #pragma asset are packed into the APK's assets rather than written to the
// filesystem, so stat(), opendir() and Poco::File cannot see them even though SDL_IOFromFile opens them
// transparently by falling back to the asset manager, which is how sound.load, pack and the datastreams reach
// them. The helpers below reproduce that lookup for the filesystem functions. Only relative paths are
// considered, matching SDL: an absolute path always addresses the real filesystem and is never an asset.
static std::mutex g_asset_manager_mutex;
static jobject g_asset_manager_object = nullptr; // Global ref; the pointer AAssetManager_fromJava hands back is only valid while this lives.
static AAssetManager* g_asset_manager = nullptr;
// Fetches the app's AssetManager, as the Java object and/or as the NDK pointer derived from it, caching both.
static bool android_get_asset_manager(JNIEnv* env, jobject* java_out, AAssetManager** native_out) {
	std::lock_guard<std::mutex> lock(g_asset_manager_mutex);
	if (!g_asset_manager) {
		LocalRef<jobject> activity(env, (jobject)SDL_GetAndroidActivity());
		if (!activity.get()) return false;
		LocalRef<jclass> activityClass(env, env->GetObjectClass(activity.get()));
		if (!activityClass.get()) return false;
		jmethodID midGetAssets = env->GetMethodID(activityClass.get(), "getAssets", "()Landroid/content/res/AssetManager;");
		if (!midGetAssets) { env->ExceptionClear(); return false; }
		LocalRef<jobject> assets(env, env->CallObjectMethod(activity.get(), midGetAssets));
		if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
		if (!assets.get()) return false;
		g_asset_manager_object = env->NewGlobalRef(assets.get());
		g_asset_manager = AAssetManager_fromJava(env, g_asset_manager_object);
		if (!g_asset_manager) {
			env->DeleteGlobalRef(g_asset_manager_object);
			g_asset_manager_object = nullptr;
			return false;
		}
	}
	if (java_out) *java_out = g_asset_manager_object;
	if (native_out) *native_out = g_asset_manager;
	return true;
}
// The asset manager addresses everything by a plain relative path, so strip the leading ./ that a script may
// reasonably have written and that the filesystem would have accepted.
static std::string android_asset_path(const std::string& path) {
	std::string p = path;
	while (p.compare(0, 2, "./") == 0) p.erase(0, 2);
	return p;
}
// The same, for a path naming a directory, which AssetManager.list wants as "sounds" rather than "sounds/".
static std::string android_asset_dir_path(const std::string& path) {
	std::string p = android_asset_path(path);
	while (!p.empty() && p.back() == '/') p.pop_back();
	return p;
}
// Opens an asset purely to learn whether it is there, since only a regular file can be opened. The caller must
// already hold a usable asset manager.
static bool android_asset_openable(AAssetManager* mgr, const std::string& path) {
	AAsset* asset = AAssetManager_open(mgr, path.c_str(), AASSET_MODE_UNKNOWN);
	if (!asset) return false;
	AAsset_close(asset);
	return true;
}
// Lists the names of everything directly inside an asset directory, files and subdirectories alike. The empty
// path is the asset root. AssetManager.list is used rather than the NDK's AAssetDir, because
// AAssetDir_getNextFileName enumerates only regular files, which would make a directory holding nothing but
// subdirectories look empty. It is documented as slow, but none of the callers here are hot paths. A missing
// path and a plain file both list as empty, so a non-empty listing is also what identifies a directory.
static bool android_asset_list_raw(const std::string& path, std::vector<std::string>& out) {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	jobject assets = nullptr;
	if (!android_get_asset_manager(env, &assets, nullptr)) return false;
	LocalRef<jclass> assetsClass(env, env->GetObjectClass(assets));
	if (!assetsClass.get()) return false;
	jmethodID midList = env->GetMethodID(assetsClass.get(), "list", "(Ljava/lang/String;)[Ljava/lang/String;");
	if (!midList) { env->ExceptionClear(); return false; }
	LocalRef<jstring> jpath(env, to_jstring(env, path));
	if (!jpath.get()) return false;
	LocalRef<jobjectArray> entries(env, (jobjectArray)env->CallObjectMethod(assets, midList, jpath.get()));
	if (env->ExceptionCheck()) { env->ExceptionClear(); return false; } // list throws IOException for paths it cannot read.
	if (!entries.get()) return false;
	jsize count = env->GetArrayLength(entries.get());
	out.reserve(out.size() + count);
	for (jsize i = 0; i < count; i++) {
		LocalRef<jstring> entry(env, (jstring)env->GetObjectArrayElement(entries.get(), i));
		if (entry.get()) out.push_back(from_jstring(env, entry.get()));
	}
	return true;
}

bool android_asset_file_exists(const std::string& path) {
	std::string p = android_asset_path(path);
	if (p.empty() || p[0] == '/') return false;
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	AAssetManager* mgr = nullptr;
	if (!android_get_asset_manager(env, nullptr, &mgr)) return false;
	return android_asset_openable(mgr, p);
}

bool android_asset_directory_exists(const std::string& path) {
	std::string p = android_asset_dir_path(path);
	if (p.empty() || p[0] == '/') return false;
	std::vector<std::string> entries;
	// A directory with no entries at all therefore reads as absent, which is harmless in practice because an
	// empty directory cannot be packed into an APK to begin with.
	return android_asset_list_raw(p, entries) && !entries.empty();
}

int64_t android_asset_file_size(const std::string& path) {
	std::string p = android_asset_path(path);
	if (p.empty() || p[0] == '/') return -1;
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return -1;
	AAssetManager* mgr = nullptr;
	if (!android_get_asset_manager(env, nullptr, &mgr)) return -1;
	AAsset* asset = AAssetManager_open(mgr, p.c_str(), AASSET_MODE_UNKNOWN);
	if (!asset) return -1;
	int64_t size = AAsset_getLength64(asset);
	AAsset_close(asset);
	return size;
}

bool android_asset_list(const std::string& path, bool directories, std::vector<std::string>& out) {
	std::string p = android_asset_dir_path(path); // May legitimately be empty here, which is the asset root.
	if (!p.empty() && p[0] == '/') return false;
	std::vector<std::string> entries;
	if (!android_asset_list_raw(p, entries)) return false;
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	AAssetManager* mgr = nullptr;
	if (!android_get_asset_manager(env, nullptr, &mgr)) return false;
	for (const std::string& entry : entries) {
		// An asset entry is either a file or a directory, and only a file opens, which is a much cheaper
		// question than listing the entry to see whether it has children of its own.
		bool is_file = android_asset_openable(mgr, p.empty() ? entry : p + "/" + entry);
		if (is_file != directories) out.push_back(entry);
	}
	return true;
}

std::string android_get_device_id() {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return "";
	LocalRef<jobject> activity(env, (jobject)SDL_GetAndroidActivity());
	if (!activity.get()) return "";
	LocalRef<jclass> activityClass(env, env->GetObjectClass(activity.get()));
	if (!activityClass.get()) return "";
	jmethodID midGetCR = env->GetMethodID(activityClass.get(), "getContentResolver", "()Landroid/content/ContentResolver;");
	if (!midGetCR) { env->ExceptionClear(); return ""; }
	LocalRef<jobject> cr(env, env->CallObjectMethod(activity.get(), midGetCR));
	if (jni_clear_exception(env) || !cr.get()) return "";
	LocalRef<jclass> settingsClass(env, env->FindClass("android/provider/Settings$Secure"));
	if (!settingsClass.get()) { env->ExceptionClear(); return ""; }
	jmethodID midGetStr = env->GetStaticMethodID(settingsClass.get(), "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
	if (!midGetStr) { env->ExceptionClear(); return ""; }
	LocalRef<jstring> key(env, to_jstring(env, "android_id"));
	if (!key.get()) return "";
	LocalRef<jstring> jresult(env, (jstring)env->CallStaticObjectMethod(settingsClass.get(), midGetStr, cr.get(), key.get()));
	if (jni_clear_exception(env)) return "";
	return from_jstring(env, jresult.get());
}

bool android_is_screen_reader_active() {
	android_setup_jni();
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	jboolean result = env->CallStaticBooleanMethod(TTSClass, midIsScreenReaderActive);
	return !jni_clear_exception(env) && result;
}

std::string android_screen_reader_detect() {
	android_setup_jni();
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return "";
	LocalRef<jstring> jreader(env, (jstring)env->CallStaticObjectMethod(TTSClass, midScreenReaderDetect));
	if (jni_clear_exception(env)) return "";
	return from_jstring(env, jreader.get());
}

bool android_screen_reader_speak(const std::string& text, bool interrupt) {
	android_setup_jni();
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	LocalRef<jstring> jtext(env, to_jstring(env, text));
	if (!jtext.get()) return false;
	jboolean result = env->CallStaticBooleanMethod(TTSClass, midScreenReaderSpeak, jtext.get(), interrupt ? JNI_TRUE : JNI_FALSE);
	return !jni_clear_exception(env) && result;
}

bool android_screen_reader_silence() {
	android_setup_jni();
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	jboolean result = env->CallStaticBooleanMethod(TTSClass, midScreenReaderSilence);
	return !jni_clear_exception(env) && result;
}

std::string android_input_box(const std::string& title, const std::string& text, const std::string& default_value) {
	android_setup_jni();
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) throw JNIException("Unable to retrieve the JNI environment");

	jmethodID mid = env->GetStaticMethodID(DialogUtilsClass, "inputBoxSync", "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
	if (!mid) {
		check_jni_exception(env, "GetStaticMethodID inputBoxSync");
		throw JNIException("Unable to find inputBoxSync method");
	}

	LocalRef<jobject> activity(env, (jobject)SDL_GetAndroidActivity());
	LocalRef<jstring> caption(env, to_jstring(env, title));
	LocalRef<jstring> prompt(env, to_jstring(env, text));
	LocalRef<jstring> default_text(env, to_jstring(env, default_value));

	LocalRef<jstring> jresult(env, static_cast<jstring>(env->CallStaticObjectMethod(DialogUtilsClass, mid, activity.get(), caption.get(), prompt.get(), default_text.get())));
	check_jni_exception(env, "CallStaticObjectMethod inputBoxSync");
	
	std::string result = from_jstring(env, jresult.get());
	
	// FIX: Check for UTF-8 encoded 'ÿ' (\xC3\xBF) which is returned on cancel
	if (result == "\xC3\xBF") {
		g_LastError = -12;
		return "";
	}
	return result;
}

bool android_info_box(const std::string& title, const std::string& text, const std::string& value) {
	android_setup_jni();
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) throw JNIException("Unable to retrieve the JNI environment");

	jmethodID mid = env->GetStaticMethodID(DialogUtilsClass, "infoBoxSync", "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
	if (!mid) {
		check_jni_exception(env, "GetStaticMethodID infoBoxSync");
		throw JNIException("Unable to find infoBoxSync method");
	}

	LocalRef<jobject> activity(env, (jobject)SDL_GetAndroidActivity());
	LocalRef<jstring> caption(env, to_jstring(env, title));
	LocalRef<jstring> prompt(env, to_jstring(env, text));
	LocalRef<jstring> info(env, to_jstring(env, value));

	env->CallStaticVoidMethod(DialogUtilsClass, mid, activity.get(), caption.get(), prompt.get(), info.get());
	check_jni_exception(env, "CallStaticVoidMethod infoBoxSync");
	return true;
}

bool android_is_window_active() {
	android_setup_jni();
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;

	jmethodID mid = env->GetStaticMethodID(DialogUtilsClass, "isWindowActive", "(Landroid/app/Activity;)Z");
	if (!mid) {
		check_jni_exception(env, "GetStaticMethodID isWindowActive");
		return false;
	}

	LocalRef<jobject> activity(env, (jobject)SDL_GetAndroidActivity());
	bool result = env->CallStaticBooleanMethod(DialogUtilsClass, mid, activity.get());
	check_jni_exception(env, "CallStaticBooleanMethod isWindowActive");
	
	return result;
}

std::vector<std::string> android_get_tts_engine_packages() {
	try {
		android_setup_jni();
	} catch (...) {
		return {};
	}
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return {};
	LocalRef<jobject> jpackageList(env, env->CallStaticObjectMethod(TTSClass, midTTSGetEnginePackages));
	if (jni_clear_exception(env) || !jpackageList.get()) return {};
	LocalRef<jclass> listClass(env, env->FindClass("java/util/List"));
	if (!listClass.get()) {
		env->ExceptionClear();
		return {};
	}
	jmethodID midSize = env->GetMethodID(listClass.get(), "size", "()I");
	jmethodID midGet = midSize ? env->GetMethodID(listClass.get(), "get", "(I)Ljava/lang/Object;") : nullptr;
	if (!midSize || !midGet) {
		env->ExceptionClear();
		return {};
	}
	jint size = env->CallIntMethod(jpackageList.get(), midSize);
	if (jni_clear_exception(env)) return {};
	std::vector<std::string> result;
	for (jint i = 0; i < size; i++) {
		LocalRef<jstring> jpackage(env, (jstring)env->CallObjectMethod(jpackageList.get(), midGet, i));
		if (jni_clear_exception(env)) break;
		if (jpackage.get()) result.push_back(from_jstring(env, jpackage.get()));
	}
	return result;
}

std::string android_get_default_tts_engine_package() {
	try { android_setup_jni(); } catch (...) { return ""; }
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return "";
	LocalRef<jstring> jresult(env, (jstring)env->CallStaticObjectMethod(TTSClass, midTTSGetDefaultEnginePackage));
	if (jni_clear_exception(env)) return "";
	return from_jstring(env, jresult.get());
}

void register_native_tts() {
	std::vector<std::string> android_engines = android_get_tts_engine_packages();
	std::string default_pkg = android_get_default_tts_engine_package();
	if (!default_pkg.empty()) tts_set_preferred_engine(default_pkg);
	for (const auto& engine_pkg : android_engines) tts_engine_register(engine_pkg, [engine_pkg]() -> std::shared_ptr<tts_engine> { return std::make_shared<android_tts_engine>(engine_pkg); });
}

// Calls a method of a Java TTS object through the calling thread's JNIEnv, answering with the fallback if there is
// no environment or the method throws. The arguments pass through JNI's variadic calls exactly as in a direct call.
template<typename... Args> static bool tts_call_bool(jobject obj, jmethodID mid, Args... args) {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env || !obj) return false;
	jboolean result = env->CallBooleanMethod(obj, mid, args...);
	return !jni_clear_exception(env) && result;
}
template<typename... Args> static int tts_call_int(jobject obj, int fallback, jmethodID mid, Args... args) {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env || !obj) return fallback;
	jint result = env->CallIntMethod(obj, mid, args...);
	return jni_clear_exception(env) ? fallback : result;
}
static float tts_call_float(jobject obj, float fallback, jmethodID mid) {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env || !obj) return fallback;
	jfloat result = env->CallFloatMethod(obj, mid);
	return jni_clear_exception(env) ? fallback : result;
}
template<typename... Args> static void tts_call_void(jobject obj, jmethodID mid, Args... args) {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env || !obj) return;
	env->CallVoidMethod(obj, mid, args...);
	jni_clear_exception(env);
}
template<typename... Args> static std::string tts_call_string(jobject obj, jmethodID mid, Args... args) {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env || !obj) return "";
	LocalRef<jstring> result(env, (jstring)env->CallObjectMethod(obj, mid, args...));
	if (jni_clear_exception(env)) return "";
	return from_jstring(env, result.get());
}

android_tts_engine::android_tts_engine(const std::string& enginePkg) : tts_engine_impl(enginePkg.empty()? "Android" : enginePkg), engine_package(enginePkg) {
	android_setup_jni(); // Provides the TTS class, found in a way that also works on a thread NVGT started.
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) throw std::runtime_error("Cannot retrieve JNI environment");
	auto method = [env](const char* name, const char* sig) {
		jmethodID mid = env->GetMethodID(TTSClass, name, sig);
		if (!mid) {
			env->ExceptionClear();
			throw std::runtime_error(std::string("Cannot find method ") + name + " on the NVGT TTS class!");
		}
		return mid;
	};
	constructor = method("<init>", "(Ljava/lang/String;)V");
	midIsActive = method("isActive", "()Z");
	midIsSpeaking = method("isSpeaking", "()Z");
	midSpeak = method("speak", "(Ljava/lang/String;Z)Z");
	midSilence = method("silence", "()Z");
	midGetVoice = method("getVoice", "()Ljava/lang/String;");
	midSetRate = method("setRate", "(F)Z");
	midSetPitch = method("setPitch", "(F)Z");
	midSetPan = method("setPan", "(F)V");
	midSetVolume = method("setVolume", "(F)V");
	midGetVoices = method("getVoices", "()Ljava/util/List;");
	midSetVoice = method("setVoice", "(Ljava/lang/String;)Z");
	midGetMaxSpeechInputLength = method("getMaxSpeechInputLength", "()I");
	midGetRate = method("getRate", "()F");
	midGetPitch = method("getPitch", "()F");
	midGetPan = method("getPan", "()F");
	midGetVolume = method("getVolume", "()F");
	midSpeakPcm = method("speakPcm", "(Ljava/lang/String;)[B");
	midGetPcmSampleRate = method("getPcmSampleRate", "()I");
	midGetPcmAudioFormat = method("getPcmAudioFormat", "()I");
	midGetPcmChannelCount = method("getPcmChannelCount", "()I");
	midGetVoiceCount = method("getVoiceCount", "()I");
	midGetVoiceName = method("getVoiceName", "(I)Ljava/lang/String;");
	midGetVoiceLanguage = method("getVoiceLanguage", "(I)Ljava/lang/String;");
	midSetVoiceByIndex = method("setVoiceByIndex", "(I)Z");
	midGetCurrentVoiceIndex = method("getCurrentVoiceIndex", "()I");
	midGetEngineLabel = method("getEngineLabel", "()Ljava/lang/String;");
	midResetRate = method("resetRate", "()Z");
	midResetPitch = method("resetPitch", "()Z");
	midResetVolume = method("resetVolume", "()Z");
	midResetVoice = method("resetVoice", "()Z");
	LocalRef<jstring> jengine(env, engine_package.empty()? nullptr : to_jstring(env, engine_package));
	if (!engine_package.empty() && !jengine.get()) throw std::runtime_error("Can't pass the engine name to the TTS object!");
	LocalRef<jobject> obj(env, env->NewObject(TTSClass, constructor, jengine.get()));
	// A restricted engine (e.g. Sao Mai Myanmar TTS) can raise a SecurityException while binding to its service. Even though the Java side now swallows it, clear any pending Java exception here as well so it can never poison a subsequent JNI call and abort the process with "No pending exception expected".
	jni_clear_exception(env);
	if (!obj.get()) throw std::runtime_error("Can't instantiate TTS object!");
	TTSObj = env->NewGlobalRef(obj.get());
	if (!TTSObj) {
		env->ExceptionClear();
		throw std::runtime_error("Can't create a global reference to the TTS object!");
	}
	// A constructor that throws never runs the destructor, so from here on a failure releases the reference itself.
	if (!is_available()) {
		env->DeleteGlobalRef(TTSObj);
		TTSObj = nullptr;
		throw std::runtime_error("TTS engine could not be initialized!");
	}
	engine_label = tts_call_string(TTSObj, midGetEngineLabel);
	if (engine_label.empty()) engine_label = engine_package;
}

// Engines live in a program-wide cache, so this normally runs only as the program exits, on whichever thread that is.
android_tts_engine::~android_tts_engine() {
	if (!TTSObj) return;
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (env) env->DeleteGlobalRef(TTSObj);
	TTSObj = nullptr;
}

bool android_tts_engine::is_available() { return tts_call_bool(TTSObj, midIsActive); }
tts_pcm_generation_state android_tts_engine::get_pcm_generation_state() { return PCM_SUPPORTED; }

bool android_tts_engine::speak(const std::string &text, bool interrupt, bool blocking) {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env || !TTSObj || text.empty()) return false;
	LocalRef<jstring> jtext(env, to_jstring(env, text));
	if (!jtext.get()) return false;
	bool result = tts_call_bool(TTSObj, midSpeak, jtext.get(), interrupt ? JNI_TRUE : JNI_FALSE);
	if (blocking) while (is_speaking()) wait(10);
	return result;
}

bool android_tts_engine::is_speaking() { return tts_call_bool(TTSObj, midIsSpeaking); }
bool android_tts_engine::stop() { return tts_call_bool(TTSObj, midSilence); }
float android_tts_engine::get_rate() { return tts_call_float(TTSObj, 1, midGetRate); }
float android_tts_engine::get_pitch() { return tts_call_float(TTSObj, 1, midGetPitch); }
float android_tts_engine::get_volume() { return tts_call_float(TTSObj, 0, midGetVolume); }
void android_tts_engine::set_rate(float rate) { tts_call_bool(TTSObj, midSetRate, rate); }
void android_tts_engine::set_pitch(float pitch) { tts_call_bool(TTSObj, midSetPitch, pitch); }
void android_tts_engine::set_volume(float volume) { tts_call_void(TTSObj, midSetVolume, volume); } // TTS.setVolume returns void.

// The reset calls hand rate, pitch, volume and voice back to the user's TTS settings (see the TTS class).
bool android_tts_engine::reset_rate() { return tts_call_bool(TTSObj, midResetRate); }
bool android_tts_engine::reset_pitch() { return tts_call_bool(TTSObj, midResetPitch); }
bool android_tts_engine::reset_volume() { return tts_call_bool(TTSObj, midResetVolume); }
bool android_tts_engine::reset_voice() { return tts_call_bool(TTSObj, midResetVoice); }

bool android_tts_engine::get_rate_range(float& minimum, float& midpoint, float& maximum) { minimum = 0.1; midpoint = 1; maximum = 6; return true; }
bool android_tts_engine::get_pitch_range(float& minimum, float& midpoint, float& maximum) { minimum = 0.25; midpoint = 1; maximum = 4; return true; }
bool android_tts_engine::get_volume_range(float& minimum, float& midpoint, float& maximum) { minimum = 0; midpoint = 0.5; maximum = 1; return true; }

int android_tts_engine::get_voice_count() { return tts_call_int(TTSObj, 0, midGetVoiceCount); }

std::string android_tts_engine::get_voice_name(int index) {
	if (!TTSObj) return "";
	return engine_label + ": " + tts_call_string(TTSObj, midGetVoiceName, (jint)index);
}

std::string android_tts_engine::get_voice_language(int index) { return tts_call_string(TTSObj, midGetVoiceLanguage, (jint)index); }
bool android_tts_engine::set_voice(int voice) { return tts_call_bool(TTSObj, midSetVoiceByIndex, (jint)voice); }
int android_tts_engine::get_current_voice() { return tts_call_int(TTSObj, -1, midGetCurrentVoiceIndex); }

tts_audio_data* android_tts_engine::speak_to_pcm(const std::string &text) {
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env || !TTSObj || text.empty()) return nullptr;
	LocalRef<jstring> jtext(env, to_jstring(env, text));
	if (!jtext.get()) return nullptr;

	// speakPcm leaves the format of what it synthesized in fields that the getters below read back afterwards, so
	// no other thread may synthesize on this shared engine in between.
	std::lock_guard<std::mutex> lock(pcm_mutex);
	LocalRef<jbyteArray> jpcmData(env, (jbyteArray)env->CallObjectMethod(TTSObj, midSpeakPcm, jtext.get()));
	if (jni_clear_exception(env) || !jpcmData.get()) return nullptr;

	// Get audio format information
	int pcmSampleRate = tts_call_int(TTSObj, 0, midGetPcmSampleRate);
	int pcmAudioFormat = tts_call_int(TTSObj, 0, midGetPcmAudioFormat);
	int pcmChannelCount = tts_call_int(TTSObj, 0, midGetPcmChannelCount);

	// Get PCM data. The bytes stay pinned until free_pcm, which may run on another thread, so they are taken through
	// a global reference to the array.
	jsize dataSize = env->GetArrayLength(jpcmData.get());
	if (dataSize <= 0) return nullptr;
	jbyteArray globalRef = (jbyteArray)env->NewGlobalRef(jpcmData.get());
	if (!globalRef) {
		env->ExceptionClear();
		return nullptr;
	}
	jbyte* pcmBytes = env->GetByteArrayElements(globalRef, NULL);
	if (!pcmBytes) {
		env->ExceptionClear();
		env->DeleteGlobalRef(globalRef);
		return nullptr;
	}

	// Convert Android AudioFormat to bitsize
	// AudioFormat.ENCODING_PCM_8BIT = 3, AudioFormat.ENCODING_PCM_16BIT = 2, AudioFormat.ENCODING_PCM_FLOAT = 4
	unsigned int bitsize;
	switch (pcmAudioFormat) {
		case 3: bitsize = 8; break;
		case 2: bitsize = 16; break;
		case 4: bitsize = 32; break;
		default: bitsize = 16; break;
	}

	return new tts_audio_data(this, pcmBytes, dataSize, pcmSampleRate, pcmChannelCount, bitsize, globalRef);
}

void android_tts_engine::free_pcm(tts_audio_data* data) {
	if (!data || !data->context) return;
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (env) {
		env->ReleaseByteArrayElements((jbyteArray)data->context, (jbyte*)data->data, 0);
		env->DeleteGlobalRef((jobject)data->context);
	}
	data->data = nullptr; // The VM's memory, never to be passed to free().
	data->context = nullptr;
	tts_engine_impl::free_pcm(data);
}

bool screen_reader_load() { return true; }
void screen_reader_unload() {}
std::string screen_reader_detect() { return android_screen_reader_detect(); }
bool screen_reader_has_speech() { return android_is_screen_reader_active(); }
bool screen_reader_has_braille() { return false; }
bool screen_reader_is_speaking() { return false; }
bool screen_reader_output(const std::string& text, bool interrupt) { return android_screen_reader_speak(text, interrupt); }
bool screen_reader_speak(const std::string& text, bool interrupt) { return android_screen_reader_speak(text, interrupt); }
bool screen_reader_braille(const std::string& text) { return false; }
bool screen_reader_silence() { return android_screen_reader_silence(); }

unsigned long long system_running_milliseconds() {
	struct timespec ts;
	if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) return 0;
	return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#endif // __ANDROID__
