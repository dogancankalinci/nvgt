/* iap_apple.mm - iOS and macOS in-app purchase implementation using StoreKit 1
 *
 * Provides iap_platform_* functions declared in iap.h for iOS and macOS builds.
 *
 * NVGT - NonVisual Gaming Toolkit
 * Copyright (c) 2022-2025 Sam Tupy
 * https://nvgt.dev
 * This software is provided "as-is", without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 * 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
*/

#include <TargetConditionals.h>
#if TARGET_OS_IOS || TARGET_OS_OSX

#import <Foundation/Foundation.h>
#import <StoreKit/StoreKit.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include "iap.h"

// --------------------------------------------------------------------------
// App Store receipt validation (PKCS7 + ASN.1 parsed with OpenSSL)
//
// Apple's receipt file is a PKCS7 signed-data container. The payload is a
// DER-encoded SET of receipt attributes, each of the form:
//   SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
// Attribute type 17 is an in_app record; its value is another SET of the
// same structure, where type 1702 = product_identifier (UTF8String) and
// type 1703 = transaction_identifier (UTF8String).
// --------------------------------------------------------------------------

// Decode one BER/DER TLV using OpenSSL's ASN1_get_object.
// On success, *val points at the value bytes and *p is advanced past them.
static bool asn1_next(const uint8_t*& p, const uint8_t* end,
                      int* tag, const uint8_t** val, size_t* vlen) {
	long length;
	int xclass;
	long omax = (long)(end - p);
	if (omax <= 0) return false;
	if (ASN1_get_object(&p, &length, tag, &xclass, omax) & 0x80) {
		ERR_clear_error();
		return false;
	}
	if (length < 0) return false;
	*vlen = (size_t)length;
	*val = p;
	p += length;
	return true;
}

static int asn1_int_val(const uint8_t* p, size_t len) {
	int v = 0;
	for (size_t i = 0; i < len && i < 4; i++) v = (v << 8) | (unsigned char)p[i];
	return v;
}

struct iap_receipt_entry { std::string product_id, transaction_id; };

// Parse the raw bytes of one in_app attribute value (itself a SET of attributes).
static iap_receipt_entry parse_in_app_value(const uint8_t* data, size_t len) {
	iap_receipt_entry e;
	const uint8_t *p = data, *end = data + len;
	int tag; const uint8_t* val; size_t vlen;

	if (!asn1_next(p, end, &tag, &val, &vlen) || tag != 0x31 /*SET*/) return e;
	p = val; end = val + vlen;

	while (p < end) {
		if (!asn1_next(p, end, &tag, &val, &vlen)) break;
		if (tag != 0x30 /*SEQUENCE*/) continue;
		const uint8_t *ap = val, *ae = val + vlen;

		int t; const uint8_t* tv; size_t tl;
		if (!asn1_next(ap, ae, &t, &tv, &tl) || t != 0x02 /*INTEGER*/) continue;
		int attr_type = asn1_int_val(tv, tl);

		// Skip version integer
		int vt; const uint8_t* vv; size_t vl;
		if (!asn1_next(ap, ae, &vt, &vv, &vl)) continue;

		// Value OCTET STRING
		int ot; const uint8_t* ov; size_t ol;
		if (!asn1_next(ap, ae, &ot, &ov, &ol) || ot != 0x04 /*OCTET STRING*/) continue;

		if (attr_type == 1702 || attr_type == 1703) {
			// The OCTET STRING wraps a UTF8String (0x0C) or IA5String (0x16)
			const uint8_t* sp = ov;
			int st; const uint8_t* sv; size_t sl;
			if (!asn1_next(sp, ov + ol, &st, &sv, &sl)) continue;
			if (st == 0x0C /*UTF8String*/ || st == 0x16 /*IA5String*/) {
				std::string s(reinterpret_cast<const char*>(sv), sl);
				if (attr_type == 1702) e.product_id    = s;
				else                   e.transaction_id = s;
			}
		}
	}
	return e;
}

// Verify the PKCS7 signature on the receipt.
//
// PKCS7_NOVERIFY skips certificate *chain* validation (we don't embed Apple's
// root CA), but it still verifies that the signature bytes were produced by the
// private key matching the signer certificate embedded in the receipt ÔÇö i.e.
// the payload has not been tampered with since it was signed.
// Additionally we confirm the signer certificate's organizationName contains
// "Apple". On a non-jailbroken device the receipt file is OS-protected so this
// combined check makes forging a receipt impractical. For a fully air-tight
// guarantee embed Apple's root CA and call PKCS7_verify with a populated
// X509_STORE instead of passing nullptr, or perform server-side validation.
static bool pkcs7_signature_valid(PKCS7* p7) {
	if (PKCS7_verify(p7, nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY) != 1)
		return false;

	STACK_OF(X509)* signers = PKCS7_get0_signers(p7, nullptr, PKCS7_NOVERIFY);
	if (!signers) return false;
	bool from_apple = false;
	for (int i = 0; i < sk_X509_num(signers); i++) {
		X509* cert = sk_X509_value(signers, i);
		char org[64] = {};
		X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
		                          NID_organizationName, org, (int)sizeof(org) - 1);
		if (std::string(org).find("Apple") != std::string::npos) {
			from_apple = true;
			break;
		}
	}
	sk_X509_free(signers);
	return from_apple;
}

// Load all in_app records from the bundle's App Store receipt.
// Returns an empty vector if the receipt is absent or cannot be parsed.
static std::vector<iap_receipt_entry> load_receipt_entries() {
	std::vector<iap_receipt_entry> result;

	NSURL*  url  = [[NSBundle mainBundle] appStoreReceiptURL];
	NSData* data = url ? [NSData dataWithContentsOfURL:url] : nil;
	if (!data || data.length == 0) return result;

	const unsigned char* ptr = (const unsigned char*)data.bytes;
	PKCS7* p7 = d2i_PKCS7(nullptr, &ptr, (long)data.length);
	if (!p7) { ERR_clear_error(); return result; }

	if (!pkcs7_signature_valid(p7)) { PKCS7_free(p7); ERR_clear_error(); return result; }

	if (!PKCS7_type_is_signed(p7) || !p7->d.sign || !p7->d.sign->contents ||
	    !PKCS7_type_is_data(p7->d.sign->contents) || !p7->d.sign->contents->d.data) {
		PKCS7_free(p7); ERR_clear_error(); return result;
	}

	ASN1_OCTET_STRING* os = p7->d.sign->contents->d.data;
	const uint8_t *p = os->data, *end = os->data + os->length;
	int tag; const uint8_t* val; size_t vlen;

	// Outer SET of top-level receipt attributes
	if (!asn1_next(p, end, &tag, &val, &vlen) || tag != 0x31 /*SET*/) {
		PKCS7_free(p7); ERR_clear_error(); return result;
	}
	p = val; end = val + vlen;

	while (p < end) {
		if (!asn1_next(p, end, &tag, &val, &vlen)) break;
		if (tag != 0x30 /*SEQUENCE*/) continue;
		const uint8_t *ap = val, *ae = val + vlen;

		int t; const uint8_t* tv; size_t tl;
		if (!asn1_next(ap, ae, &t, &tv, &tl) || t != 0x02) continue;
		int attr_type = asn1_int_val(tv, tl);

		int vt; const uint8_t* vv; size_t vl;
		if (!asn1_next(ap, ae, &vt, &vv, &vl)) continue;

		int ot; const uint8_t* ov; size_t ol;
		if (!asn1_next(ap, ae, &ot, &ov, &ol) || ot != 0x04) continue;

		if (attr_type == 17 /*in_app*/) {
			auto e = parse_in_app_value(ov, ol);
			if (!e.product_id.empty()) result.push_back(e);
		}
	}

	PKCS7_free(p7);
	ERR_clear_error();
	return result;
}

// Returns true when product_id + transaction_id appear together in the
// pre-loaded receipt entries. Accepts the entries as a parameter so the
// caller can load the receipt once per transaction batch rather than once
// per individual transaction.
static bool receipt_contains(const std::vector<iap_receipt_entry>& entries,
                             const std::string& product_id,
                             const std::string& transaction_id) {
	if (product_id.empty() || transaction_id.empty()) return false;
	for (const auto& e : entries) {
		if (e.product_id == product_id && e.transaction_id == transaction_id)
			return true;
	}
	return false;
}

// --------------------------------------------------------------------------
// IAPManager: Objective-C class that bridges StoreKit to iap_shared_state
// --------------------------------------------------------------------------
@interface IAPManager : NSObject <SKProductsRequestDelegate, SKPaymentTransactionObserver>
@property (nonatomic, strong) SKProductsRequest* activeRequest;
@property (nonatomic, strong) NSMutableDictionary<NSString*, SKProduct*>* productMap;
@end

@implementation IAPManager

- (instancetype)init {
	self = [super init];
	if (self) {
		_productMap = [NSMutableDictionary new];
		[[SKPaymentQueue defaultQueue] addTransactionObserver:self];
	}
	return self;
}

- (void)dealloc {
	[[SKPaymentQueue defaultQueue] removeTransactionObserver:self];
	[super dealloc];
}

// ----- SKProductsRequestDelegate -----

- (void)productsRequest:(SKProductsRequest*)request
     didReceiveResponse:(SKProductsResponse*)response {
	std::vector<iap_product_info> products;
	for (SKProduct* product in response.products) {
		iap_product_info info;
		info.product_id    = [product.productIdentifier UTF8String];
		info.title         = [product.localizedTitle UTF8String];
		info.description   = [product.localizedDescription UTF8String];

		// Format price with locale
		NSNumberFormatter* fmt = [[NSNumberFormatter alloc] init];
		fmt.formatterBehavior = NSNumberFormatterBehavior10_4;
		fmt.numberStyle       = NSNumberFormatterCurrencyStyle;
		fmt.locale            = product.priceLocale;
		NSString* priceStr    = [fmt stringFromNumber:product.price];
		[fmt release];
		info.price         = priceStr ? [priceStr UTF8String] : "";
		info.price_micros  = [product.price doubleValue] * 1000000.0;
		NSString* currency = [product.priceLocale objectForKey:NSLocaleCurrencyCode];
		info.currency_code = currency ? [currency UTF8String] : "";

		// Cache the SKProduct for launching payments
		self.productMap[product.productIdentifier] = product;
		products.push_back(info);
	}
	{
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.products       = products;
		g_iap.products_ready = true;
		g_iap.querying_products = false;
		if (response.invalidProductIdentifiers.count > 0) {
			NSString* inv = [response.invalidProductIdentifiers componentsJoinedByString:@", "];
			g_iap.last_error = "Invalid product IDs: " + std::string([inv UTF8String]);
		}
	}
	self.activeRequest = nil;
}

- (void)request:(SKRequest*)request didFailWithError:(NSError*)error {
	std::string msg = error ? [error.localizedDescription UTF8String] : "Unknown SKRequest error";
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.last_error        = msg;
	g_iap.products_ready    = true; // signal done even on error
	g_iap.querying_products = false;
	self.activeRequest = nil;
}

// ----- SKPaymentTransactionObserver -----

- (void)paymentQueue:(SKPaymentQueue*)queue
 updatedTransactions:(NSArray<SKPaymentTransaction*>*)transactions {
	// Load the receipt once for the entire batch. Each transaction validation
	// call re-using this snapshot avoids repeated disk reads and PKCS7 parses.
	const std::vector<iap_receipt_entry> receipt = load_receipt_entries();

	for (SKPaymentTransaction* tx in transactions) {
		switch (tx.transactionState) {
			case SKPaymentTransactionStatePurchased:
			case SKPaymentTransactionStateRestored: {
				iap_purchase_info info;
				info.product_id      = [tx.payment.productIdentifier UTF8String];
				bool is_restored     = (tx.transactionState == SKPaymentTransactionStateRestored);
				info.state           = is_restored ? IAP_PURCHASE_RESTORED : IAP_PURCHASE_SUCCESS;

				// For restored purchases StoreKit delivers a new transaction, but the receipt
				// records the original transaction's identifier (field 1703). Use the original
				// transaction ID both for receipt lookup and as the exposed transaction_id so
				// that server-side validation and record-keeping see a consistent identifier.
				NSString* receipt_tx_ns = (is_restored && tx.originalTransaction)
				    ? tx.originalTransaction.transactionIdentifier
				    : tx.transactionIdentifier;
				std::string receipt_tx = receipt_tx_ns ? [receipt_tx_ns UTF8String] : "";
				info.transaction_id  = receipt_tx;

				if (!receipt_contains(receipt, info.product_id, receipt_tx)) {
					info.state = IAP_PURCHASE_FAILED;
					std::lock_guard<std::mutex> lk(g_iap.mtx);
					g_iap.last_error = "Receipt validation failed: " + info.product_id
					                 + " not found in App Store receipt";
					g_iap.pending_purchases.push_back(info);
					[[SKPaymentQueue defaultQueue] finishTransaction:tx];
					break;
				}

				std::lock_guard<std::mutex> lk(g_iap.mtx);
				g_iap.pending_purchases.push_back(info);
				[[SKPaymentQueue defaultQueue] finishTransaction:tx];
				break;
			}
			case SKPaymentTransactionStateFailed: {
				iap_purchase_info info;
				info.product_id     = [tx.payment.productIdentifier UTF8String];
				info.transaction_id = "";
				int errCode = tx.error ? (int)tx.error.code : 0;
				info.state = (errCode == SKErrorPaymentCancelled) ? IAP_PURCHASE_CANCELLED : IAP_PURCHASE_FAILED;
				std::string errMsg = tx.error ? [tx.error.localizedDescription UTF8String] : "Unknown payment error";
				{
					std::lock_guard<std::mutex> lk(g_iap.mtx);
					g_iap.last_error = errMsg;
					g_iap.pending_purchases.push_back(info);
				}
				[[SKPaymentQueue defaultQueue] finishTransaction:tx];
				break;
			}
			case SKPaymentTransactionStateDeferred: {
				iap_purchase_info info;
				info.product_id     = [tx.payment.productIdentifier UTF8String];
				info.transaction_id = tx.transactionIdentifier ? [tx.transactionIdentifier UTF8String] : "";
				info.state          = IAP_PURCHASE_DEFERRED;
				std::lock_guard<std::mutex> lk(g_iap.mtx);
				g_iap.pending_purchases.push_back(info);
				break;
			}
			case SKPaymentTransactionStatePurchasing:
				// In-progress; nothing to report yet
				break;
		}
	}
}

- (void)paymentQueueRestoreCompletedTransactionsFinished:(SKPaymentQueue*)queue {
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.restore_finished = true;
	g_iap.restoring_purchases = false;
}

- (void)paymentQueue:(SKPaymentQueue*)queue
restoreCompletedTransactionsFailedWithError:(NSError*)error {
	std::string msg = error ? [error.localizedDescription UTF8String] : "Restore failed";
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.last_error = msg;
	g_iap.restore_finished = true;
	g_iap.restoring_purchases = false;
}

@end

// --------------------------------------------------------------------------
// Singleton accessor
// --------------------------------------------------------------------------
static IAPManager* g_iap_manager = nil;

static IAPManager* iap_get_manager() {
	if (!g_iap_manager) g_iap_manager = [[IAPManager alloc] init];
	return g_iap_manager;
}

// --------------------------------------------------------------------------
// Platform function implementations
// --------------------------------------------------------------------------
void iap_platform_set_public_key(const std::string& /*key*/) {}

bool iap_platform_available() {
	return [SKPaymentQueue canMakePayments] == YES;
}

bool iap_platform_query_products(const std::vector<std::string>& ids) {
	NSMutableSet<NSString*>* set = [NSMutableSet new];
	for (const auto& id : ids)
		[set addObject:[NSString stringWithUTF8String:id.c_str()]];
	{
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.products_ready    = false;
		g_iap.querying_products = true;
	}
	IAPManager* mgr = iap_get_manager();
	mgr.activeRequest = [[[SKProductsRequest alloc] initWithProductIdentifiers:set] autorelease];
	mgr.activeRequest.delegate = mgr;
	[mgr.activeRequest start];
	[set release];
	return true;
}

bool iap_platform_purchase(const std::string& product_id) {
	IAPManager* mgr = iap_get_manager();
	NSString* pid = [NSString stringWithUTF8String:product_id.c_str()];
	SKProduct* product = mgr.productMap[pid];
	if (!product) {
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.last_error = "Product not found in cache: " + product_id + " ÔÇö call iap_query_products first";
		return false;
	}
	SKPayment* payment = [SKPayment paymentWithProduct:product];
	[[SKPaymentQueue defaultQueue] addPayment:payment];
	return true;
}

bool iap_platform_restore_purchases() {
	{
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.restore_finished = false;
		g_iap.restoring_purchases = true;
	}
	[[SKPaymentQueue defaultQueue] restoreCompletedTransactions];
	return true;
}

bool iap_platform_acknowledge_purchase(const std::string&) { return true; }
bool iap_platform_consume_purchase(const std::string&)     { return true; }

void iap_platform_init() {
	iap_get_manager(); // Attach SKPaymentTransactionObserver at engine startup
}

#endif // TARGET_OS_IOS || TARGET_OS_OSX
