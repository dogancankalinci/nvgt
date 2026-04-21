/* iap.cpp - in-app purchase support for iOS/macOS (StoreKit) and Android (Google Play Billing)
 *
 * Platform implementations:
 *   iOS/macOS: iap_apple.mm (StoreKit 1 via Objective-C++)
 *   Android:   this file under #ifdef __ANDROID__ (Google Play Billing via JNI)
 *   Others:    stub implementations that report IAP as unavailable
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

#include "iap.h"
#include "nvgt_angelscript.h"
#include <angelscript.h>
#include <scriptarray.h>
#include <chrono>
#include <string>
#include <vector>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#ifndef TARGET_OS_IOS
#define TARGET_OS_IOS 0
#endif
#ifndef TARGET_OS_OSX
#define TARGET_OS_OSX 0
#endif

// --------------------------------------------------------------------------
// Shared async state definition
// --------------------------------------------------------------------------
iap_shared_state g_iap;

// --------------------------------------------------------------------------
// Android implementation via JNI
// --------------------------------------------------------------------------
#if defined(__ANDROID__) && !defined(NVGT_NO_IAP)
#include <jni.h>
#include <SDL3/SDL.h>
#include <Poco/Exception.h>
#include <string_view>

static jclass     g_billing_class         = nullptr;
static jmethodID  g_mid_is_available      = nullptr;
static jmethodID  g_mid_set_public_key    = nullptr;
static jmethodID  g_mid_query_products    = nullptr;
static jmethodID  g_mid_purchase_product  = nullptr;
static jmethodID  g_mid_restore_purchases = nullptr;
static jmethodID  g_mid_acknowledge       = nullptr;
static jmethodID  g_mid_consume           = nullptr;

static jclass   g_product_info_class    = nullptr;
static jfieldID g_fid_pi_product_id    = nullptr;
static jfieldID g_fid_pi_title         = nullptr;
static jfieldID g_fid_pi_description   = nullptr;
static jfieldID g_fid_pi_price         = nullptr;
static jfieldID g_fid_pi_currency_code = nullptr;
static jfieldID g_fid_pi_price_micros  = nullptr;

static jclass   g_purchase_info_class      = nullptr;
static jfieldID g_fid_pur_product_id      = nullptr;
static jfieldID g_fid_pur_transaction_id  = nullptr;
static jfieldID g_fid_pur_purchase_token  = nullptr;
static jfieldID g_fid_pur_state           = nullptr;

static std::once_flag g_jni_init_flag;

static std::string jni_describe_and_clear_exception(JNIEnv* env, std::string_view context) {
	if (!env || !env->ExceptionCheck()) return "";
	jthrowable ex = env->ExceptionOccurred();
	env->ExceptionClear();
	std::string details(context);
	if (ex) {
		jclass throwable_class = env->FindClass("java/lang/Throwable");
		if (throwable_class) {
			jmethodID to_string = env->GetMethodID(throwable_class, "toString", "()Ljava/lang/String;");
			if (to_string) {
				jstring text = (jstring)env->CallObjectMethod(ex, to_string);
				if (!env->ExceptionCheck()) {
					const char* utf = text ? env->GetStringUTFChars(text, nullptr) : nullptr;
					if (utf) {
						details += ": ";
						details += utf;
						env->ReleaseStringUTFChars(text, utf);
					}
				} else env->ExceptionClear();
				if (text) env->DeleteLocalRef(text);
			}
			env->DeleteLocalRef(throwable_class);
		}
		env->DeleteLocalRef(ex);
	}
	return details;
}

static bool jni_check_and_store_exception(JNIEnv* env, std::string_view context) {
	std::string err = jni_describe_and_clear_exception(env, context);
	if (err.empty()) return false;
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.last_error = err;
	return true;
}

static std::string jstring_to_std(JNIEnv* env, jstring js) {
	if (!js) return "";
	const char* utf = env->GetStringUTFChars(js, nullptr);
	if (!utf) return "";
	std::string s(utf);
	env->ReleaseStringUTFChars(js, utf);
	return s;
}

// Read a String field from a JNI object.
static std::string get_string_field(JNIEnv* env, jobject obj, jfieldID fid) {
	jstring js = (jstring)env->GetObjectField(obj, fid);
	std::string s = jstring_to_std(env, js);
	if (js) env->DeleteLocalRef(js);
	return s;
}

static std::vector<iap_product_info> product_array_to_vector(JNIEnv* env, jobjectArray arr) {
	std::vector<iap_product_info> products;
	if (!arr) return products;
	jsize len = env->GetArrayLength(arr);
	products.reserve((size_t)len);
	for (jsize i = 0; i < len; i++) {
		jobject obj = env->GetObjectArrayElement(arr, i);
		if (!obj) continue;
		iap_product_info p;
		p.product_id    = get_string_field(env, obj, g_fid_pi_product_id);
		p.title         = get_string_field(env, obj, g_fid_pi_title);
		p.description   = get_string_field(env, obj, g_fid_pi_description);
		p.price         = get_string_field(env, obj, g_fid_pi_price);
		p.currency_code = get_string_field(env, obj, g_fid_pi_currency_code);
		p.price_micros  = (double)env->GetLongField(obj, g_fid_pi_price_micros);
		env->DeleteLocalRef(obj);
		products.push_back(p);
	}
	return products;
}

static std::vector<iap_purchase_info> purchase_array_to_vector(JNIEnv* env, jobjectArray arr) {
	std::vector<iap_purchase_info> purchases;
	if (!arr) return purchases;
	jsize len = env->GetArrayLength(arr);
	purchases.reserve((size_t)len);
	for (jsize i = 0; i < len; i++) {
		jobject obj = env->GetObjectArrayElement(arr, i);
		if (!obj) continue;
		iap_purchase_info p;
		p.product_id      = get_string_field(env, obj, g_fid_pur_product_id);
		p.transaction_id  = get_string_field(env, obj, g_fid_pur_transaction_id);
		p.purchase_token  = get_string_field(env, obj, g_fid_pur_purchase_token);
		p.state           = env->GetIntField(obj, g_fid_pur_state);
		env->DeleteLocalRef(obj);
		purchases.push_back(p);
	}
	return purchases;
}

static void iap_android_set_last_error(const std::string& err) {
	if (err.empty()) return;
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.last_error = err;
}

extern "C" JNIEXPORT void JNICALL
Java_com_samtupy_nvgt_BillingManager_nativeSetProducts(JNIEnv* env, jclass, jobjectArray products, jstring error) {
	std::vector<iap_product_info> converted = product_array_to_vector(env, products);
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.products = std::move(converted);
	g_iap.products_ready = true;
	g_iap.querying_products = false;
	std::string err = jstring_to_std(env, error);
	if (!err.empty()) g_iap.last_error = err;
}

extern "C" JNIEXPORT void JNICALL
Java_com_samtupy_nvgt_BillingManager_nativeAddPendingPurchases(JNIEnv* env, jclass, jobjectArray purchases, jstring error) {
	std::vector<iap_purchase_info> converted = purchase_array_to_vector(env, purchases);
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.pending_purchases.insert(g_iap.pending_purchases.end(), converted.begin(), converted.end());
	std::string err = jstring_to_std(env, error);
	if (!err.empty()) g_iap.last_error = err;
}

extern "C" JNIEXPORT void JNICALL
Java_com_samtupy_nvgt_BillingManager_nativeSetLastError(JNIEnv* env, jclass, jstring error) {
	iap_android_set_last_error(jstring_to_std(env, error));
}

extern "C" JNIEXPORT void JNICALL
Java_com_samtupy_nvgt_BillingManager_nativeFinishRestore(JNIEnv* env, jclass, jstring error) {
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.restore_finished = true;
	g_iap.restoring_purchases = false;
	std::string err = jstring_to_std(env, error);
	if (!err.empty()) g_iap.last_error = err;
}

extern "C" JNIEXPORT void JNICALL
Java_com_samtupy_nvgt_BillingManager_nativeFinishOp(JNIEnv*, jclass, jboolean success) {
	std::lock_guard<std::mutex> lk(g_iap.op_mtx);
	g_iap.op_result = (bool)success;
	g_iap.op_pending = false;
	g_iap.op_cv.notify_all();
}

static void iap_android_setup_jni() {
	// std::call_once guarantees:
	//   - Thread-safe single initialisation.
	//   - If the callable throws the flag is NOT set, so the next caller retries.
	//   - Globals are written only after every lookup succeeds (all-or-nothing).
	std::call_once(g_jni_init_flag, []() {
		JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
		if (!env) throw Poco::Exception("iap: cannot retrieve JNI environment");
		jclass local = nullptr;
		jclass pi_local = nullptr;
		jclass pur_local = nullptr;
		try {
			local = env->FindClass("com/samtupy/nvgt/BillingManager");
			if (!local) {
				jni_check_and_store_exception(env, "FindClass BillingManager");
				throw Poco::Exception("iap: cannot find BillingManager class");
			}

			auto get_mid = [&](const char* name, const char* sig) -> jmethodID {
				jmethodID mid = env->GetStaticMethodID(local, name, sig);
				if (!mid) {
					jni_check_and_store_exception(env, std::string("GetStaticMethodID ") + name);
					throw Poco::Exception(std::string("iap: GetStaticMethodID failed for ") + name);
				}
				return mid;
			};

			auto get_fid = [&](jclass cls, const char* name, const char* sig) -> jfieldID {
				jfieldID fid = env->GetFieldID(cls, name, sig);
				if (!fid) {
					jni_check_and_store_exception(env, std::string("GetFieldID ") + name);
					throw Poco::Exception(std::string("iap: GetFieldID failed for ") + name);
				}
				return fid;
			};

			// Resolve every method ID before touching any globals so that a failure
			// here does not leave globals in a partially-initialised state.
			jmethodID mid_is_available      = get_mid("isAvailable",        "()Z");
			jmethodID mid_set_public_key    = get_mid("setPublicKey",        "(Ljava/lang/String;)V");
			jmethodID mid_query_products    = get_mid("queryProducts",       "([Ljava/lang/String;)V");
			jmethodID mid_purchase_product  = get_mid("purchaseProduct",     "(Ljava/lang/String;)Z");
			jmethodID mid_restore_purchases = get_mid("restorePurchases",    "()V");
			jmethodID mid_acknowledge       = get_mid("acknowledgePurchase", "(Ljava/lang/String;)V");
			jmethodID mid_consume           = get_mid("consumePurchase",     "(Ljava/lang/String;)V");

			pi_local = env->FindClass("com/samtupy/nvgt/BillingManager$ProductInfo");
			if (!pi_local) {
				jni_check_and_store_exception(env, "FindClass BillingManager$ProductInfo");
				throw Poco::Exception("iap: cannot find BillingManager$ProductInfo class");
			}
			jfieldID fid_pi_product_id    = get_fid(pi_local, "productId",    "Ljava/lang/String;");
			jfieldID fid_pi_title         = get_fid(pi_local, "title",        "Ljava/lang/String;");
			jfieldID fid_pi_description   = get_fid(pi_local, "description",  "Ljava/lang/String;");
			jfieldID fid_pi_price         = get_fid(pi_local, "price",        "Ljava/lang/String;");
			jfieldID fid_pi_currency_code = get_fid(pi_local, "currencyCode", "Ljava/lang/String;");
			jfieldID fid_pi_price_micros  = get_fid(pi_local, "priceMicros",  "J");

			pur_local = env->FindClass("com/samtupy/nvgt/BillingManager$PurchaseInfo");
			if (!pur_local) {
				jni_check_and_store_exception(env, "FindClass BillingManager$PurchaseInfo");
				throw Poco::Exception("iap: cannot find BillingManager$PurchaseInfo class");
			}
			jfieldID fid_pur_product_id      = get_fid(pur_local, "productId",      "Ljava/lang/String;");
			jfieldID fid_pur_transaction_id  = get_fid(pur_local, "transactionId",  "Ljava/lang/String;");
			jfieldID fid_pur_purchase_token  = get_fid(pur_local, "purchaseToken",  "Ljava/lang/String;");
			jfieldID fid_pur_state           = get_fid(pur_local, "state",          "I");

			// All resolutions succeeded — commit to globals (all-or-nothing)
			g_billing_class         = (jclass)env->NewGlobalRef(local);
			env->DeleteLocalRef(local);
			local = nullptr;
			g_mid_is_available      = mid_is_available;
			g_mid_set_public_key    = mid_set_public_key;
			g_mid_query_products    = mid_query_products;
			g_mid_purchase_product  = mid_purchase_product;
			g_mid_restore_purchases = mid_restore_purchases;
			g_mid_acknowledge       = mid_acknowledge;
			g_mid_consume           = mid_consume;

			g_product_info_class    = (jclass)env->NewGlobalRef(pi_local);
			env->DeleteLocalRef(pi_local);
			pi_local = nullptr;
			g_fid_pi_product_id    = fid_pi_product_id;
			g_fid_pi_title         = fid_pi_title;
			g_fid_pi_description   = fid_pi_description;
			g_fid_pi_price         = fid_pi_price;
			g_fid_pi_currency_code = fid_pi_currency_code;
			g_fid_pi_price_micros  = fid_pi_price_micros;

			g_purchase_info_class      = (jclass)env->NewGlobalRef(pur_local);
			env->DeleteLocalRef(pur_local);
			pur_local = nullptr;
			g_fid_pur_product_id      = fid_pur_product_id;
			g_fid_pur_transaction_id  = fid_pur_transaction_id;
			g_fid_pur_purchase_token  = fid_pur_purchase_token;
			g_fid_pur_state           = fid_pur_state;
		} catch (...) {
			if (pur_local) env->DeleteLocalRef(pur_local);
			if (pi_local) env->DeleteLocalRef(pi_local);
			if (local) env->DeleteLocalRef(local);
			throw;
		}
	});
}

void iap_platform_set_public_key(const std::string& key) {
	try { iap_android_setup_jni(); } catch (...) { return; }
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return;
	jstring js = env->NewStringUTF(key.c_str());
	env->CallStaticVoidMethod(g_billing_class, g_mid_set_public_key, js);
	jni_check_and_store_exception(env, "BillingManager.setPublicKey");
	env->DeleteLocalRef(js);
}

bool iap_platform_available() {
	try { iap_android_setup_jni(); } catch (...) { return false; }
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	bool available = (bool)env->CallStaticBooleanMethod(g_billing_class, g_mid_is_available);
	return !jni_check_and_store_exception(env, "BillingManager.isAvailable") && available;
}

bool iap_platform_query_products(const std::vector<std::string>& ids) {
	try { iap_android_setup_jni(); } catch (...) { return false; }
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;

	jclass string_class = env->FindClass("java/lang/String");
	jobjectArray arr = env->NewObjectArray((jsize)ids.size(), string_class, nullptr);
	for (size_t i = 0; i < ids.size(); i++) {
		jstring js = env->NewStringUTF(ids[i].c_str());
		env->SetObjectArrayElement(arr, (jsize)i, js);
		env->DeleteLocalRef(js);
	}
	env->DeleteLocalRef(string_class);

	{
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.products.clear();
		g_iap.last_error.clear();
		g_iap.products_ready = false;
		g_iap.querying_products = true;
	}
	env->CallStaticVoidMethod(g_billing_class, g_mid_query_products, arr);
	if (jni_check_and_store_exception(env, "BillingManager.queryProducts")) {
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.products_ready = true;
		g_iap.querying_products = false;
		env->DeleteLocalRef(arr);
		return false;
	}
	env->DeleteLocalRef(arr);
	return true;
}

bool iap_platform_purchase(const std::string& product_id) {
	try { iap_android_setup_jni(); } catch (...) { return false; }
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	jstring js = env->NewStringUTF(product_id.c_str());
	bool ok = (bool)env->CallStaticBooleanMethod(g_billing_class, g_mid_purchase_product, js);
	if (jni_check_and_store_exception(env, "BillingManager.purchaseProduct")) ok = false;
	env->DeleteLocalRef(js);
	return ok;
}

bool iap_platform_restore_purchases() {
	try { iap_android_setup_jni(); } catch (...) { return false; }
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	{
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.restore_finished = false;
		g_iap.restoring_purchases = true;
	}
	env->CallStaticVoidMethod(g_billing_class, g_mid_restore_purchases);
	if (jni_check_and_store_exception(env, "BillingManager.restorePurchases")) {
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.restore_finished = true;
		g_iap.restoring_purchases = false;
		return false;
	}
	return true;
}

bool iap_platform_acknowledge_purchase(const std::string& purchase_token) {
	try { iap_android_setup_jni(); } catch (...) { return false; }
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	{
		std::lock_guard<std::mutex> lk(g_iap.op_mtx);
		g_iap.op_pending = true;
		g_iap.op_result = false;
	}
	jstring js = env->NewStringUTF(purchase_token.c_str());
	env->CallStaticVoidMethod(g_billing_class, g_mid_acknowledge, js);
	env->DeleteLocalRef(js);
	if (jni_check_and_store_exception(env, "BillingManager.acknowledgePurchase")) {
		std::lock_guard<std::mutex> lk(g_iap.op_mtx);
		g_iap.op_pending = false;
		return false;
	}
	std::unique_lock<std::mutex> lk(g_iap.op_mtx);
	g_iap.op_cv.wait_for(lk, std::chrono::seconds(15), []{ return !g_iap.op_pending; });
	g_iap.op_pending = false;
	return g_iap.op_result;
}

bool iap_platform_consume_purchase(const std::string& purchase_token) {
	try { iap_android_setup_jni(); } catch (...) { return false; }
	JNIEnv* env = (JNIEnv*)SDL_GetAndroidJNIEnv();
	if (!env) return false;
	{
		std::lock_guard<std::mutex> lk(g_iap.op_mtx);
		g_iap.op_pending = true;
		g_iap.op_result = false;
	}
	jstring js = env->NewStringUTF(purchase_token.c_str());
	env->CallStaticVoidMethod(g_billing_class, g_mid_consume, js);
	env->DeleteLocalRef(js);
	if (jni_check_and_store_exception(env, "BillingManager.consumePurchase")) {
		std::lock_guard<std::mutex> lk(g_iap.op_mtx);
		g_iap.op_pending = false;
		return false;
	}
	std::unique_lock<std::mutex> lk(g_iap.op_mtx);
	g_iap.op_cv.wait_for(lk, std::chrono::seconds(15), []{ return !g_iap.op_pending; });
	g_iap.op_pending = false;
	return g_iap.op_result;
}

void iap_platform_init() {}

#endif // defined(__ANDROID__) && !defined(NVGT_NO_IAP)

// --------------------------------------------------------------------------
// Stub implementations for platforms without IAP support (Windows, Linux, and NVGT_NO_IAP builds)
// --------------------------------------------------------------------------
#if (!defined(__ANDROID__) && !TARGET_OS_IOS && !TARGET_OS_OSX) || defined(NVGT_NO_IAP)

void iap_platform_set_public_key(const std::string&)                 {}
bool iap_platform_available()                                        { return false; }
bool iap_platform_query_products(const std::vector<std::string>&)    { return false; }
bool iap_platform_purchase(const std::string&)                       { return false; }
bool iap_platform_restore_purchases()                                { return false; }
bool iap_platform_acknowledge_purchase(const std::string&)           { return false; }
bool iap_platform_consume_purchase(const std::string&)               { return false; }
void iap_platform_init()                                             {}

#endif

bool script_iap_purchase::consume() {
	return iap_platform_consume_purchase(info.purchase_token);
}

bool script_iap_purchase::acknowledge() {
	return iap_platform_acknowledge_purchase(info.purchase_token);
}

// --------------------------------------------------------------------------
// AngelScript-callable wrappers
// --------------------------------------------------------------------------
static void as_iap_set_android_public_key(const std::string& key) {
	iap_platform_set_public_key(key);
}

static bool as_iap_available() {
	return iap_platform_available();
}

static bool as_iap_query_products(CScriptArray* ids) {
	if (!ids) return false;
	std::vector<std::string> product_ids;
	product_ids.reserve(ids->GetSize());
	for (asUINT i = 0; i < ids->GetSize(); i++)
		product_ids.push_back(*static_cast<std::string*>(ids->At(i)));
	ids->Release();
	return iap_platform_query_products(product_ids);
}

static bool as_iap_products_ready() {
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	return g_iap.products_ready;
}

static CScriptArray* as_iap_get_products() {
	asIScriptContext* ctx = asGetActiveContext();
	if (!ctx) return nullptr;
	asIScriptEngine* engine = ctx->GetEngine();
	asITypeInfo* t = engine->GetTypeInfoByDecl("array<iap_product@>");
	if (!t) return nullptr;

	std::vector<iap_product_info> snapshot;
	{
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		snapshot = g_iap.products;
	}

	CScriptArray* arr = CScriptArray::Create(t, (asUINT)snapshot.size());
	for (asUINT i = 0; i < (asUINT)snapshot.size(); i++) {
		script_iap_product* p = new script_iap_product();
		p->info = snapshot[i];
		arr->SetValue(i, &p);
		p->release(); // array incremented the refcount via SetValue
	}
	return arr;
}

static bool as_iap_purchase(const std::string& product_id) {
	bool found = false;
	{
		std::lock_guard<std::mutex> lk(g_iap.mtx); // Scope the lock
		for (const auto& p : g_iap.products) {
			if (p.product_id == product_id) { found = true; break; }
		}
	} // Lock releases here
	if (found) return iap_platform_purchase(product_id);
	return false;
}

static bool as_iap_restore_purchases() {
	return iap_platform_restore_purchases();
}

static bool as_iap_restore_finished() {
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	return g_iap.restore_finished && !g_iap.restoring_purchases;
}

static CScriptArray* as_iap_get_pending_purchases() {
	asIScriptContext* ctx = asGetActiveContext();
	if (!ctx) return nullptr;
	asIScriptEngine* engine = ctx->GetEngine();
	asITypeInfo* t = engine->GetTypeInfoByDecl("array<iap_purchase@>");
	if (!t) return nullptr;

	std::vector<iap_purchase_info> drained;
	{
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		drained.swap(g_iap.pending_purchases);
	}

	CScriptArray* arr = CScriptArray::Create(t, (asUINT)drained.size());
	for (asUINT i = 0; i < (asUINT)drained.size(); i++) {
		script_iap_purchase* p = new script_iap_purchase();
		p->info = drained[i];
		arr->SetValue(i, &p);
		p->release();
	}
	return arr;
}

static std::string as_iap_get_last_error() {
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	return g_iap.last_error;
}

// --------------------------------------------------------------------------
// AngelScript registration
// --------------------------------------------------------------------------
void RegisterIAP(asIScriptEngine* engine) {
	iap_platform_init();

	// Purchase state enum
	engine->RegisterEnum("iap_purchase_state");
	engine->RegisterEnumValue("iap_purchase_state", "IAP_PURCHASE_SUCCESS",   IAP_PURCHASE_SUCCESS);
	engine->RegisterEnumValue("iap_purchase_state", "IAP_PURCHASE_CANCELLED", IAP_PURCHASE_CANCELLED);
	engine->RegisterEnumValue("iap_purchase_state", "IAP_PURCHASE_FAILED",    IAP_PURCHASE_FAILED);
	engine->RegisterEnumValue("iap_purchase_state", "IAP_PURCHASE_RESTORED",  IAP_PURCHASE_RESTORED);
	engine->RegisterEnumValue("iap_purchase_state", "IAP_PURCHASE_PENDING",   IAP_PURCHASE_PENDING);
	engine->RegisterEnumValue("iap_purchase_state", "IAP_PURCHASE_DEFERRED",  IAP_PURCHASE_DEFERRED);

	// iap_product reference type
	engine->RegisterObjectType("iap_product", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("iap_product", asBEHAVE_ADDREF,  "void f()", asMETHOD(script_iap_product, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("iap_product", asBEHAVE_RELEASE, "void f()", asMETHOD(script_iap_product, release), asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_product", "string get_product_id() const property",    asMETHOD(script_iap_product, get_product_id),    asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_product", "string get_title() const property",         asMETHOD(script_iap_product, get_title),         asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_product", "string get_description() const property",   asMETHOD(script_iap_product, get_description),   asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_product", "string get_price() const property",         asMETHOD(script_iap_product, get_price),         asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_product", "string get_currency_code() const property", asMETHOD(script_iap_product, get_currency_code), asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_product", "double get_price_micros() const property",  asMETHOD(script_iap_product, get_price_micros),  asCALL_THISCALL);

	// iap_purchase reference type
	engine->RegisterObjectType("iap_purchase", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("iap_purchase", asBEHAVE_ADDREF,  "void f()", asMETHOD(script_iap_purchase, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("iap_purchase", asBEHAVE_RELEASE, "void f()", asMETHOD(script_iap_purchase, release), asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_purchase", "string get_product_id() const property",       asMETHOD(script_iap_purchase, get_product_id),     asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_purchase", "string get_transaction_id() const property",   asMETHOD(script_iap_purchase, get_transaction_id), asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_purchase", "iap_purchase_state get_state() const property",asMETHOD(script_iap_purchase, get_state),          asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_purchase", "bool get_is_pending() const property",         asMETHOD(script_iap_purchase, get_is_pending),     asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_purchase", "bool consume()",     asMETHOD(script_iap_purchase, consume),     asCALL_THISCALL);
	engine->RegisterObjectMethod("iap_purchase", "bool acknowledge()", asMETHOD(script_iap_purchase, acknowledge), asCALL_THISCALL);

	// Global functions
	engine->RegisterGlobalFunction("void iap_set_android_public_key(const string &in key)",
		asFUNCTION(as_iap_set_android_public_key), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool iap_available()",
		asFUNCTION(as_iap_available), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool iap_query_products(string[]@ product_ids)",
		asFUNCTION(as_iap_query_products), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool iap_products_ready()",
		asFUNCTION(as_iap_products_ready), asCALL_CDECL);
	engine->RegisterGlobalFunction("iap_product@[]@ iap_get_products()",
		asFUNCTION(as_iap_get_products), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool iap_purchase_product(const string &in product_id)",
		asFUNCTION(as_iap_purchase), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool iap_restore_purchases()",
		asFUNCTION(as_iap_restore_purchases), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool iap_restore_finished()",
		asFUNCTION(as_iap_restore_finished), asCALL_CDECL);
	engine->RegisterGlobalFunction("iap_purchase@[]@ iap_get_pending_purchases()",
		asFUNCTION(as_iap_get_pending_purchases), asCALL_CDECL);
	engine->RegisterGlobalFunction("string iap_get_last_error()",
		asFUNCTION(as_iap_get_last_error), asCALL_CDECL);
}
