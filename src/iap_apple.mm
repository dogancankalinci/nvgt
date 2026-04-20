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
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <time.h>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include "iap.h"

// iOS/iPadOS: need UIDevice for identifierForVendor.
// macOS and Mac Catalyst: need IOKit for the primary network interface MAC address.
#if TARGET_OS_OSX || TARGET_OS_MACCATALYST
#import <IOKit/IOKitLib.h>
#elif TARGET_OS_IOS
#import <UIKit/UIKit.h>
#endif

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

// Decode a UTF8String (0x0C) or IA5String (0x16) wrapped inside an OCTET STRING value.
static std::string asn1_decode_string(const uint8_t* ov, size_t ol) {
	const uint8_t* sp = ov;
	int st; const uint8_t* sv; size_t sl;
	if (!asn1_next(sp, ov + ol, &st, &sv, &sl)) return {};
	if (st != 0x0C /*UTF8String*/ && st != 0x16 /*IA5String*/) return {};
	return std::string(reinterpret_cast<const char*>(sv), sl);
}

// Parse an ISO 8601 receipt date string (e.g. "2023-01-01T12:00:00Z") to UTC time_t.
static time_t parse_receipt_date(const std::string& s) {
	if (s.size() < 19) return 0;
	char buf[32] = {};
	if (s.size() >= sizeof(buf)) return 0;
	memcpy(buf, s.c_str(), s.size());
	struct tm t = {};
	if (strptime(buf, "%Y-%m-%dT%H:%M:%SZ", &t) != nullptr ||
	    strptime(buf, "%Y-%m-%dT%H:%M:%S+00:00", &t) != nullptr)
		return timegm(&t);
	return 0;
}

// --------------------------------------------------------------------------
// Platform-specific device identifier for SHA-1 hash verification.
// iOS/iPadOS: raw UUID bytes from identifierForVendor (16 bytes).
// macOS/Mac Catalyst: MAC address bytes from primary network interface.
// --------------------------------------------------------------------------
#if TARGET_OS_OSX || TARGET_OS_MACCATALYST
static io_service_t mac_io_service(const char* bsdName, bool wantBuiltIn) {
	mach_port_t port = kIOMasterPortDefault;
	CFMutableDictionaryRef matching = IOBSDNameMatching(port, 0, bsdName);
	if (!matching) return IO_OBJECT_NULL;
	io_iterator_t it = IO_OBJECT_NULL;
	if (IOServiceGetMatchingServices(port, matching, &it) != KERN_SUCCESS || it == IO_OBJECT_NULL)
		return IO_OBJECT_NULL;
	io_service_t result = IO_OBJECT_NULL;
	for (io_service_t candidate = IOIteratorNext(it);
	     candidate != IO_OBJECT_NULL;
	     candidate = IOIteratorNext(it)) {
		CFTypeRef prop = IORegistryEntryCreateCFProperty(candidate, CFSTR("IOBuiltin"),
		                                                  kCFAllocatorDefault, 0);
		bool match = (prop && CFGetTypeID(prop) == CFBooleanGetTypeID() &&
		              (bool)CFBooleanGetValue((CFBooleanRef)prop) == wantBuiltIn);
		if (prop) CFRelease(prop);
		if (match) { result = candidate; break; }
		IOObjectRelease(candidate);
	}
	IOObjectRelease(it);
	return result;
}

static std::vector<uint8_t> device_identifier_bytes() {
	io_service_t svc = mac_io_service("en0", true);
	if (svc == IO_OBJECT_NULL) svc = mac_io_service("en1", true);
	if (svc == IO_OBJECT_NULL) svc = mac_io_service("en0", false);
	if (svc == IO_OBJECT_NULL) return {};
	std::vector<uint8_t> result;
	CFTypeRef prop = IORegistryEntrySearchCFProperty(svc, kIOServicePlane,
	                                                  CFSTR("IOMACAddress"),
	                                                  kCFAllocatorDefault,
	                                                  kIORegistryIterateRecursively |
	                                                  kIORegistryIterateParents);
	if (prop && CFGetTypeID(prop) == CFDataGetTypeID()) {
		CFDataRef d = (CFDataRef)prop;
		result.assign(CFDataGetBytePtr(d), CFDataGetBytePtr(d) + CFDataGetLength(d));
	}
	if (prop) CFRelease(prop);
	IOObjectRelease(svc);
	return result;
}
#else // iOS, iPadOS
static std::vector<uint8_t> device_identifier_bytes() {
	NSUUID* uuid = [[UIDevice currentDevice] identifierForVendor];
	if (!uuid) return {};
	uuid_t bytes;
	[uuid getUUIDBytes:bytes];
	return std::vector<uint8_t>(bytes, bytes + sizeof(uuid_t));
}
#endif

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
			std::string s = asn1_decode_string(ov, ol);
			if (attr_type == 1702) e.product_id    = s;
			else                   e.transaction_id = s;
		}
	}
	return e;
}

// Verify the PKCS7 signature on the receipt.
//
// PKCS7_NOVERIFY skips certificate *chain* validation (we don't embed Apple's
// root CA), but still verifies the signature bytes against the embedded signer
// certificate — i.e. the payload has not been tampered with since it was signed.
// Additionally we confirm the signer certificate's organizationName contains
// "Apple". The creation_time parameter (from receipt field 12) is passed as the
// X509_STORE verification time so that certificates valid at signing time are
// accepted even if they have since expired, per Apple's recommendation.
static bool pkcs7_signature_valid(PKCS7* p7, time_t creation_time) {
	X509_STORE* store = X509_STORE_new();
	if (store && creation_time > 0) {
		X509_VERIFY_PARAM* param = X509_STORE_get0_param(store);
		if (param) X509_VERIFY_PARAM_set_time(param, creation_time);
	}
	int rc = PKCS7_verify(p7, nullptr, store, nullptr, nullptr, PKCS7_NOVERIFY);
	if (store) X509_STORE_free(store);
	if (rc != 1) return false;

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

// Load, parse, and fully validate the App Store receipt.
//
// Performs all Apple-recommended local checks (without embedding the root CA):
//   1. PKCS7 signature verified using receipt_creation_date (field 12) as the
//      certificate verification time, so signing-time validity is used.
//   2. Bundle identifier (field 2) must match NSBundle.mainBundle.bundleIdentifier.
//   3. App version string (field 3) must match CFBundleVersion.
//   4. SHA-1 device hash (field 5) must equal SHA1(deviceId || opaqueValue || bundleIdRaw),
//      where deviceId is platform-specific (identifierForVendor on iOS,
//      MAC address on macOS/Catalyst).
//
// Returns in_app entries (field 17) on success; empty vector on any failure.
// *out_refresh_recommended is set to true only when the failure is due to the receipt
// file being absent or PKCS7-corrupt — cases where SKReceiptRefreshRequest can help.
// It is NOT set for bundle ID / version / hash mismatches; those cannot be fixed by
// a refresh and should result in an immediate failure.
static std::vector<iap_receipt_entry> load_receipt_entries(bool* out_refresh_recommended = nullptr) {
	if (out_refresh_recommended) *out_refresh_recommended = false;
	std::vector<iap_receipt_entry> result;

	NSURL*  url  = [[NSBundle mainBundle] appStoreReceiptURL];
	NSData* data = url ? [NSData dataWithContentsOfURL:url] : nil;
	if (!data || data.length == 0) {
		if (out_refresh_recommended) *out_refresh_recommended = true;
		return result;
	}

	const unsigned char* ptr = (const unsigned char*)data.bytes;
	PKCS7* p7 = d2i_PKCS7(nullptr, &ptr, (long)data.length);
	if (!p7) {
		ERR_clear_error();
		if (out_refresh_recommended) *out_refresh_recommended = true;
		return result;
	}

	if (!PKCS7_type_is_signed(p7) || !p7->d.sign || !p7->d.sign->contents ||
	    !PKCS7_type_is_data(p7->d.sign->contents) || !p7->d.sign->contents->d.data) {
		PKCS7_free(p7); ERR_clear_error();
		if (out_refresh_recommended) *out_refresh_recommended = true;
		return result;
	}

	ASN1_OCTET_STRING* os = p7->d.sign->contents->d.data;
	const uint8_t *p = os->data, *end = os->data + os->length;

	// Fields extracted during the single parse pass
	std::string bundle_id, app_version, creation_date;
	std::vector<uint8_t> bundle_id_raw, opaque_value, sha1_hash;

	int tag; const uint8_t* val; size_t vlen;
	if (!asn1_next(p, end, &tag, &val, &vlen) || tag != 0x31 /*SET*/) {
		PKCS7_free(p7); ERR_clear_error(); return result;
	}
	p = val; end = val + vlen;

	while (p < end) {
		if (!asn1_next(p, end, &tag, &val, &vlen)) break;
		if (tag != 0x30 /*SEQUENCE*/) continue;
		const uint8_t *ap = val, *ae = val + vlen;

		int t; const uint8_t* tv; size_t tl;
		if (!asn1_next(ap, ae, &t, &tv, &tl) || t != 0x02 /*INTEGER*/) continue;
		int attr_type = asn1_int_val(tv, tl);

		int vt; const uint8_t* vv; size_t vl;
		if (!asn1_next(ap, ae, &vt, &vv, &vl)) continue;

		int ot; const uint8_t* ov; size_t ol;
		if (!asn1_next(ap, ae, &ot, &ov, &ol) || ot != 0x04 /*OCTET STRING*/) continue;

		switch (attr_type) {
			case 2: // bundle_id
				bundle_id_raw.assign(ov, ov + ol); // raw DER bytes used in SHA-1
				bundle_id = asn1_decode_string(ov, ol);
				break;
			case 3: // app_version (CFBundleVersion)
				app_version = asn1_decode_string(ov, ol);
				break;
			case 4: // opaque_value — used in SHA-1 hash
				opaque_value.assign(ov, ov + ol);
				break;
			case 5: // sha1_hash — 20-byte device hash to verify
				sha1_hash.assign(ov, ov + ol);
				break;
			case 12: // receipt_creation_date — used as PKCS7 verification time
				creation_date = asn1_decode_string(ov, ol);
				break;
			case 17: { // in_app purchase record
				auto e = parse_in_app_value(ov, ol);
				if (!e.product_id.empty()) result.push_back(e);
				break;
			}
		}
	}

	// Step 1: PKCS7 signature, using receipt_creation_date as the verification time.
	// A signature failure means the receipt file is corrupt or tampered; a refresh may fix it.
	time_t creation_time = parse_receipt_date(creation_date);
	if (!pkcs7_signature_valid(p7, creation_time)) {
		PKCS7_free(p7); ERR_clear_error();
		if (out_refresh_recommended) *out_refresh_recommended = true;
		return {};
	}
	PKCS7_free(p7);

	// Step 2: Bundle identifier must match the running app.
	NSString* expected_bid_ns = [[NSBundle mainBundle] bundleIdentifier];
	std::string expected_bid = expected_bid_ns ? [expected_bid_ns UTF8String] : "";
	if (!expected_bid.empty() && bundle_id != expected_bid) {
		ERR_clear_error(); return {};
	}

	// Step 3: App version (CFBundleVersion build string) must match.
	NSString* expected_ver_ns = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
	std::string expected_ver = expected_ver_ns ? [expected_ver_ns UTF8String] : "";
	if (!expected_ver.empty() && app_version != expected_ver) {
		ERR_clear_error(); return {};
	}

	// Step 4: Device SHA-1 hash — SHA1(deviceId || opaqueValue || bundleIdRaw).
	if (!sha1_hash.empty() && sha1_hash.size() == SHA_DIGEST_LENGTH &&
	    !opaque_value.empty() && !bundle_id_raw.empty()) {
		std::vector<uint8_t> dev_id = device_identifier_bytes();
		if (!dev_id.empty()) {
			uint8_t computed[SHA_DIGEST_LENGTH];
			SHA_CTX ctx;
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, dev_id.data(), dev_id.size());
			SHA1_Update(&ctx, opaque_value.data(), opaque_value.size());
			SHA1_Update(&ctx, bundle_id_raw.data(), bundle_id_raw.size());
			SHA1_Final(computed, &ctx);
			if (memcmp(computed, sha1_hash.data(), SHA_DIGEST_LENGTH) != 0) {
				ERR_clear_error(); return {};
			}
		}
	}

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
@property (nonatomic, strong) SKReceiptRefreshRequest* receiptRefreshRequest;
// Purchased/Restored transactions held back while a receipt refresh is in progress.
// They are NOT finished yet so StoreKit will re-deliver them after the observer
// is re-attached on refresh success.  On refresh failure they are explicitly failed
// and finished so the queue is not permanently blocked.
@property (nonatomic, strong) NSMutableArray<SKPaymentTransaction*>* pendingReceiptTransactions;
@end

@implementation IAPManager

- (instancetype)init {
	self = [super init];
	if (self) {
		_productMap = [NSMutableDictionary new];
		_pendingReceiptTransactions = [NSMutableArray new];
		[[SKPaymentQueue defaultQueue] addTransactionObserver:self];
	}
	return self;
}

- (void)dealloc {
	[[SKPaymentQueue defaultQueue] removeTransactionObserver:self];
	[super dealloc];
}

// Initiates an async App Store receipt refresh (SKReceiptRefreshRequest).
// Called when receipt validation fails in a way that a fresh receipt can fix
// (missing file or PKCS7-corrupt). Does nothing if a refresh is already running.
// Per Apple's guidelines: don't terminate the app on a missing/corrupt receipt.
- (void)requestReceiptRefresh {
	if (self.receiptRefreshRequest) return; // already in progress
	self.receiptRefreshRequest = [[[SKReceiptRefreshRequest alloc] initWithReceiptProperties:nil] autorelease];
	self.receiptRefreshRequest.delegate = self;
	[self.receiptRefreshRequest start];
}

// Validates and finishes one Purchased/Restored transaction against a receipt that
// has already passed all structural checks.  Shared by the normal transaction path
// and the post-refresh retry path.
- (void)finishValidatedTransaction:(SKPaymentTransaction*)tx
                           receipt:(const std::vector<iap_receipt_entry>&)receipt {
	bool is_restored = (tx.transactionState == SKPaymentTransactionStateRestored);
	iap_purchase_info info;
	info.product_id = [tx.payment.productIdentifier UTF8String];
	info.state      = is_restored ? IAP_PURCHASE_RESTORED : IAP_PURCHASE_SUCCESS;

	NSString* receipt_tx_ns = (is_restored && tx.originalTransaction)
	    ? tx.originalTransaction.transactionIdentifier
	    : tx.transactionIdentifier;
	std::string receipt_tx = receipt_tx_ns ? [receipt_tx_ns UTF8String] : "";
	info.transaction_id = receipt_tx;

	if (!receipt_contains(receipt, info.product_id, receipt_tx)) {
		info.state = IAP_PURCHASE_FAILED;
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.last_error = "Receipt validation failed: " + info.product_id
		                 + " not found in App Store receipt";
		g_iap.pending_purchases.push_back(info);
	} else {
		std::lock_guard<std::mutex> lk(g_iap.mtx);
		g_iap.pending_purchases.push_back(info);
	}
	[[SKPaymentQueue defaultQueue] finishTransaction:tx];
}

// ----- SKRequestDelegate (shared by SKProductsRequest and SKReceiptRefreshRequest) -----

// On receipt refresh success: load the now-refreshed receipt and directly validate
// and finish every deferred transaction.  No observer remove/re-add needed.
- (void)requestDidFinish:(SKRequest*)request {
	if (request != self.receiptRefreshRequest) return;
	self.receiptRefreshRequest = nil;

	NSArray<SKPaymentTransaction*>* deferred = [self.pendingReceiptTransactions copy];
	[self.pendingReceiptTransactions removeAllObjects];

	bool refresh_recommended = false;
	const std::vector<iap_receipt_entry> receipt = load_receipt_entries(&refresh_recommended);

	for (SKPaymentTransaction* tx in deferred) {
		if (refresh_recommended) {
			// Receipt still unusable after refresh — fail immediately rather than
			// looping.  The queue must not be left blocked indefinitely.
			iap_purchase_info info;
			info.product_id     = [tx.payment.productIdentifier UTF8String];
			info.transaction_id = tx.transactionIdentifier ? [tx.transactionIdentifier UTF8String] : "";
			info.state          = IAP_PURCHASE_FAILED;
			{
				std::lock_guard<std::mutex> lk(g_iap.mtx);
				g_iap.last_error = "Receipt still invalid after refresh: " + info.product_id;
				g_iap.pending_purchases.push_back(info);
			}
			[[SKPaymentQueue defaultQueue] finishTransaction:tx];
		} else {
			[self finishValidatedTransaction:tx receipt:receipt];
		}
	}
	[deferred release];
}

- (void)request:(SKRequest*)request didFailWithError:(NSError*)error {
	std::string msg = error ? [error.localizedDescription UTF8String] : "Unknown SKRequest error";
	if (request == self.receiptRefreshRequest) {
		self.receiptRefreshRequest = nil;
		// Receipt refresh failed — fail and finish every deferred transaction so
		// the StoreKit queue is not permanently blocked.
		{
			std::lock_guard<std::mutex> lk(g_iap.mtx);
			g_iap.last_error = "Receipt refresh failed: " + msg;
			for (SKPaymentTransaction* tx in self.pendingReceiptTransactions) {
				iap_purchase_info info;
				info.product_id     = [tx.payment.productIdentifier UTF8String];
				info.transaction_id = tx.transactionIdentifier ? [tx.transactionIdentifier UTF8String] : "";
				info.state          = IAP_PURCHASE_FAILED;
				g_iap.pending_purchases.push_back(info);
			}
		}
		for (SKPaymentTransaction* tx in self.pendingReceiptTransactions)
			[[SKPaymentQueue defaultQueue] finishTransaction:tx];
		[self.pendingReceiptTransactions removeAllObjects];
		return;
	}
	// Products request failure
	std::lock_guard<std::mutex> lk(g_iap.mtx);
	g_iap.last_error        = msg;
	g_iap.products_ready    = true; // signal done even on error
	g_iap.querying_products = false;
	self.activeRequest = nil;
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

// ----- SKPaymentTransactionObserver -----

- (void)paymentQueue:(SKPaymentQueue*)queue
 updatedTransactions:(NSArray<SKPaymentTransaction*>*)transactions {
	// Load and fully validate the receipt once for the entire batch.
	// out_refresh_recommended is true only when the failure is recoverable via
	// SKReceiptRefreshRequest (missing file or PKCS7-corrupt), NOT for hard
	// mismatches (bundle ID, version, SHA-1) which a refresh cannot fix.
	bool refresh_recommended = false;
	const std::vector<iap_receipt_entry> receipt = load_receipt_entries(&refresh_recommended);

	for (SKPaymentTransaction* tx in transactions) {
		switch (tx.transactionState) {
			case SKPaymentTransactionStatePurchased:
			case SKPaymentTransactionStateRestored: {
				// If the receipt is corrupt or missing, defer this transaction:
				// do NOT call finishTransaction so StoreKit keeps it in the queue.
				// After the refresh completes, requestDidFinish: validates and finishes
				// every deferred transaction directly from pendingReceiptTransactions.
				if (refresh_recommended) {
					[self.pendingReceiptTransactions addObject:tx];
					[self requestReceiptRefresh];
					break;
				}

				[self finishValidatedTransaction:tx receipt:receipt];
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
		g_iap.last_error = "Product not found in cache: " + product_id + " — call iap_query_products first";
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
