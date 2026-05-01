/* iap.h - in-app purchase support for iOS/macOS (StoreKit) and Android (Google Play Billing)
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
#include <angelscript.h>
#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

// Purchase completion states exposed to AngelScript
enum iap_purchase_state {
	IAP_PURCHASE_SUCCESS = 0,
	IAP_PURCHASE_CANCELLED = 1,
	IAP_PURCHASE_FAILED = 2,
	IAP_PURCHASE_RESTORED = 3,
	IAP_PURCHASE_PENDING = 4,
	IAP_PURCHASE_DEFERRED = 5
};

// Internal product description filled by platform callbacks
struct iap_product_info {
	std::string product_id;
	std::string title;
	std::string description;
	std::string price;          // Formatted string, e.g. "$0.99"
	std::string currency_code;
	double price_micros = 0.0;  // price * 1,000,000 for exact arithmetic
};

// Internal purchase record filled by platform callbacks
struct iap_purchase_info {
	std::string product_id;
	std::string transaction_id;
	std::string purchase_token; // Android: required for acknowledge/consume
	int state = IAP_PURCHASE_FAILED;
};

// Shared async state: platform callbacks write here, AngelScript reads via polling
struct iap_shared_state {
	std::mutex mtx;
	bool products_ready = false;
	bool querying_products = false;
	bool restore_finished = false;
	bool restoring_purchases = false;
	std::vector<iap_product_info> products;
	std::vector<iap_purchase_info> pending_purchases; // drained by iap_get_pending_purchases
	std::string last_error;

	// Synchronisation for blocking consume/acknowledge calls
	std::mutex op_mtx;
	std::condition_variable op_cv;
	bool op_pending = false;
	bool op_result = false;
};

extern iap_shared_state g_iap;

// Platform-specific functions - defined in iap.cpp (Android + stubs) or iap_apple.mm (iOS/macOS)
void iap_platform_set_public_key(const std::string& key);
bool iap_platform_available();
bool iap_platform_query_products(const std::vector<std::string>& ids);
bool iap_platform_purchase(const std::string& product_id);
bool iap_platform_restore_purchases();
bool iap_platform_acknowledge_purchase(const std::string& purchase_token);
bool iap_platform_consume_purchase(const std::string& purchase_token);
void iap_platform_init();

// AngelScript-exposed product object (reference counted)
class script_iap_product {
	mutable int refcount;
public:
	iap_product_info info;
	script_iap_product() : refcount(1) {}
	void add_ref() { asAtomicInc(refcount); }
	void release() { if (asAtomicDec(refcount) < 1) delete this; }
	std::string get_product_id() const { return info.product_id; }
	std::string get_title() const { return info.title; }
	std::string get_description() const { return info.description; }
	std::string get_price() const { return info.price; }
	std::string get_currency_code() const { return info.currency_code; }
	double get_price_micros() const { return info.price_micros; }
};

// AngelScript-exposed purchase object (reference counted)
class script_iap_purchase {
	mutable int refcount;
public:
	iap_purchase_info info;
	script_iap_purchase() : refcount(1) {}
	void add_ref() { asAtomicInc(refcount); }
	void release() { if (asAtomicDec(refcount) < 1) delete this; }
	std::string get_product_id() const { return info.product_id; }
	std::string get_transaction_id() const { return info.transaction_id; }
	iap_purchase_state get_state() const { return (iap_purchase_state)info.state; }
	bool get_is_pending() const {
		return info.state == IAP_PURCHASE_PENDING || info.state == IAP_PURCHASE_DEFERRED;
	}
	bool consume();
	bool acknowledge();
};

void RegisterIAP(asIScriptEngine* engine);
