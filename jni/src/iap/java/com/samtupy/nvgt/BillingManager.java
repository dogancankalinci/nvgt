// BillingManager.java - Google Play Billing Library integration for NVGT
//
// All public static methods are called from C++ via JNI (iap.cpp).
// Async results flow back to C++ through native callbacks on this class.
//
// JNI interface:
//   nativeSetProducts(ProductInfo[], String)
//   nativeAddPendingPurchases(PurchaseInfo[], String)
//   nativeSetLastError(String)
//   States: SUCCESS=0, CANCELLED=1, FAILED=2, RESTORED=3, PENDING=4, DEFERRED=5
//
// FRAUD PREVENTION
// ----------------
// Lucky Patcher and similar tools attack in two ways:
//
//   1. Fake billing service (no/low root): Intercepts the IInAppBillingService
//      AIDL and returns fabricated Purchase objects.  Defeated here by verifying
//      each purchase's RSA signature (SHA1withRSA) against your app's Google Play
//      public key - the attacker cannot forge a signature without Google's private key.
//
//   2. APK patching (requires root): Rewrites app bytecode to skip checks.
//      Client-side code cannot fully stop this; only server-side purchase
//      verification via the Google Play Developer API can.
//
// To enable signature verification call setPublicKey() with the Base64 RSA public
// key found in Play Console ÔåÆ Your app ÔåÆ Monetize ÔåÆ Monetization setup ÔåÆ Licensing.
//
// NVGT - NonVisual Gaming Toolkit
// Copyright (c) 2022-2026 Sam Tupy - https://nvgt.dev

package com.samtupy.nvgt;

import android.app.Activity;
import android.util.Base64;
import androidx.annotation.NonNull;
import com.android.billingclient.api.*;
import org.libsdl.app.SDL;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class BillingManager implements PurchasesUpdatedListener {

	// Purchase state constants - must match iap_purchase_state in iap.h
	private static final int STATE_SUCCESS   = 0;
	private static final int STATE_CANCELLED = 1;
	private static final int STATE_FAILED    = 2;
	private static final int STATE_RESTORED  = 3;
	private static final int STATE_PENDING   = 4;
	private static final int STATE_DEFERRED  = 5;

	// -------------------------------------------------------------------------
	// Data transfer objects returned to C++ via JNI
	// -------------------------------------------------------------------------
	public static class ProductInfo {
		public final String productId;
		public final String title;
		public final String description;
		public final String price;
		public final String currencyCode;
		public final long   priceMicros;
		ProductInfo(String productId, String title, String description,
		            String price, String currencyCode, long priceMicros) {
			this.productId    = productId;
			this.title        = title;
			this.description  = description;
			this.price        = price;
			this.currencyCode = currencyCode;
			this.priceMicros  = priceMicros;
		}
	}

	public static class PurchaseInfo {
		public final String  productId;
		public final String  transactionId;
		public final String  purchaseToken;
		public final int     state;
		PurchaseInfo(String productId, String transactionId, String purchaseToken,
		             int state) {
			this.productId      = productId;
			this.transactionId  = transactionId;
			this.purchaseToken  = purchaseToken;
			this.state          = state;
		}
	}

	// -------------------------------------------------------------------------
	// Singleton
	// -------------------------------------------------------------------------
	private static volatile BillingManager sInstance;
	private static final Object sInstanceLock = new Object();

	private final BillingClient billingClient;
	private final Object connectionLock = new Object();
	private final List<Runnable> pendingConnectedCallbacks = new ArrayList<>();
	private final List<Runnable> pendingConnectionFailures = new ArrayList<>();
	private boolean isConnecting = false;

	// Product cache used by purchaseProduct().
	private final List<ProductDetails> productDetailsList = Collections.synchronizedList(new ArrayList<>());
	private volatile boolean clientConnected = false;
	private volatile String  lastError       = "";

	// Cached product ID of the purchase currently in progress, used to populate
	// the cancellation record when USER_CANCELED arrives with no purchase objects.
	private volatile String activePurchaseProductId = null;

	// RSA public key set by the developer via setPublicKey().
	// When null, signature verification is skipped (not recommended for production).
	private static volatile String sPublicKey = null;

	private BillingManager(Activity activity) {
		billingClient = BillingClient.newBuilder(activity.getApplicationContext())
				.setListener(this)
				.enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
				.build();
	}

	private static native void nativeSetProducts(ProductInfo[] products, String error);
	private static native void nativeAddPendingPurchases(PurchaseInfo[] purchases, String error);
	private static native void nativeSetLastError(String error);
	private static native void nativeFinishRestore(String error);
	private static native void nativeFinishOp(boolean success);

	public static BillingManager getInstance() {
		if (sInstance == null) {
			synchronized (sInstanceLock) {
				if (sInstance == null) {
					Activity activity = (Activity) SDL.getContext();
					if (activity == null)
						throw new IllegalStateException("SDL activity not available");
					sInstance = new BillingManager(activity);
				}
			}
		}
		return sInstance;
	}

	// -------------------------------------------------------------------------
	// Connection helpers
	// -------------------------------------------------------------------------
	private void ensureConnected(Runnable onConnected) {
		ensureConnected(onConnected, null);
	}

	private void ensureConnected(Runnable onConnected, Runnable onFailure) {
		Runnable immediateCallback = null;
		boolean startConnection = false;
		synchronized (connectionLock) {
			if (clientConnected && billingClient.isReady()) {
				immediateCallback = onConnected;
			} else {
				if (onConnected != null) pendingConnectedCallbacks.add(onConnected);
				if (onFailure != null) pendingConnectionFailures.add(onFailure);
				if (!isConnecting) {
					isConnecting = true;
					startConnection = true;
				}
			}
		}
		if (immediateCallback != null) {
			immediateCallback.run();
			return;
		}
		if (!startConnection) return;
		try {
			billingClient.startConnection(new BillingClientStateListener() {
				@Override
				public void onBillingSetupFinished(@NonNull BillingResult result) {
					List<Runnable> successCallbacks;
					List<Runnable> failureCallbacks;
					if (result.getResponseCode() == BillingClient.BillingResponseCode.OK) {
						synchronized (connectionLock) {
							clientConnected = true;
							isConnecting = false;
							successCallbacks = new ArrayList<>(pendingConnectedCallbacks);
							failureCallbacks = new ArrayList<>();
							pendingConnectedCallbacks.clear();
							pendingConnectionFailures.clear();
						}
						for (Runnable callback : successCallbacks) callback.run();
					} else {
						reportError(result.getDebugMessage());
						synchronized (connectionLock) {
							clientConnected = false;
							isConnecting = false;
							successCallbacks = new ArrayList<>();
							failureCallbacks = new ArrayList<>(pendingConnectionFailures);
							pendingConnectedCallbacks.clear();
							pendingConnectionFailures.clear();
						}
						for (Runnable callback : failureCallbacks) callback.run();
					}
				}
				@Override
				public void onBillingServiceDisconnected() {
					synchronized (connectionLock) {
						clientConnected = false;
						isConnecting = false;
					}
					reportError("Billing service disconnected");
				}
			});
		} catch (RuntimeException ex) {
			reportError(ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName());
			List<Runnable> failureCallbacks;
			synchronized (connectionLock) {
				clientConnected = false;
				isConnecting = false;
				failureCallbacks = new ArrayList<>(pendingConnectionFailures);
				pendingConnectedCallbacks.clear();
				pendingConnectionFailures.clear();
			}
			for (Runnable callback : failureCallbacks) callback.run();
		}
	}

	private void reportError(String error) {
		lastError = (error != null) ? error : "";
		if (!lastError.isEmpty()) nativeSetLastError(lastError);
	}

	private ProductInfo[] snapshotProducts() {
		synchronized (productDetailsList) {
			List<ProductInfo> result = new ArrayList<>();
			for (ProductDetails pd : productDetailsList) {
				String price = "", currency = "";
				long micros = 0;
				ProductDetails.OneTimePurchaseOfferDetails oneTime = pd.getOneTimePurchaseOfferDetails();
				if (oneTime != null) {
					price = oneTime.getFormattedPrice();
					currency = oneTime.getPriceCurrencyCode();
					micros = oneTime.getPriceAmountMicros();
				} else {
					List<ProductDetails.SubscriptionOfferDetails> subs = pd.getSubscriptionOfferDetails();
					if (subs != null && !subs.isEmpty()) {
						List<ProductDetails.PricingPhase> phases = subs.get(0).getPricingPhases().getPricingPhaseList();
						if (!phases.isEmpty()) {
							ProductDetails.PricingPhase phase = phases.get(0);
							price = phase.getFormattedPrice();
							currency = phase.getPriceCurrencyCode();
							micros = phase.getPriceAmountMicros();
						}
					}
				}
				result.add(new ProductInfo(
						pd.getProductId(), pd.getTitle(), pd.getDescription(),
						price, currency, micros));
			}
			return result.toArray(new ProductInfo[0]);
		}
	}

	// -------------------------------------------------------------------------
	// Purchase signature verification
	// -------------------------------------------------------------------------

	/**
	 * Verifies the SHA1withRSA signature Google Play attaches to every purchase.
	 * This is the primary defence against fake billing services (Lucky Patcher et al.).
	 *
	 * Returns true if:
	 *   - No public key has been set (developer hasn't configured verification), OR
	 *   - The cryptographic signature is valid.
	 * Returns false if the signature is invalid or verification throws.
	 */
	private static boolean verifyPurchaseSignature(Purchase purchase) {
		String key = sPublicKey;
		if (key == null || key.isEmpty()) return true; // verification not configured

		try {
			byte[]         keyBytes   = Base64.decode(key, Base64.DEFAULT);
			PublicKey      publicKey  = KeyFactory.getInstance("RSA")
			                               .generatePublic(new X509EncodedKeySpec(keyBytes));
			Signature      sig        = Signature.getInstance("SHA1withRSA");
			sig.initVerify(publicKey);
			sig.update(purchase.getOriginalJson().getBytes("UTF-8"));
			byte[]         sigBytes   = Base64.decode(purchase.getSignature(), Base64.DEFAULT);
			return sig.verify(sigBytes);
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * fraud check
	 * Returns null on success, or a human-readable reason string on failure.
	 */
	private static String fraudCheck(Purchase purchase) {
		if (!verifyPurchaseSignature(purchase))
			return "Purchase signature invalid - possible fraud (Lucky Patcher?)";
		return null; // passed
	}

	// -------------------------------------------------------------------------
	// PurchasesUpdatedListener
	// -------------------------------------------------------------------------
	@Override
	public void onPurchasesUpdated(@NonNull BillingResult result, List<Purchase> purchases) {
		if (result.getResponseCode() == BillingClient.BillingResponseCode.OK && purchases != null) {
			List<PurchaseInfo> completed = new ArrayList<>();
			for (Purchase purchase : purchases) {
				String fraud = fraudCheck(purchase);
				if (fraud != null) {
					reportError(fraud);
					// Report as FAILED so the script can react (e.g. log, alert)
					List<String> products = purchase.getProducts();
					String productId = products.isEmpty() ? "" : products.get(0);
					completed.add(new PurchaseInfo(productId, "", "", STATE_FAILED));
					continue;
				}
				completed.add(buildPurchaseInfo(purchase, STATE_SUCCESS));
			}
			activePurchaseProductId = null;
			if (!completed.isEmpty()) nativeAddPendingPurchases(completed.toArray(new PurchaseInfo[0]), null);
		} else if (result.getResponseCode() == BillingClient.BillingResponseCode.USER_CANCELED) {
			String pid = activePurchaseProductId != null ? activePurchaseProductId : "";
			activePurchaseProductId = null;
			nativeAddPendingPurchases(new PurchaseInfo[] {
					new PurchaseInfo(pid, "", "", STATE_CANCELLED)
			}, null);
		} else {
			reportError(result.getDebugMessage());
			String pid = activePurchaseProductId != null ? activePurchaseProductId : "";
			activePurchaseProductId = null;
			nativeAddPendingPurchases(new PurchaseInfo[] {
					new PurchaseInfo(pid, "", "", STATE_FAILED)
			}, lastError);
		}
	}

	private PurchaseInfo buildPurchaseInfo(Purchase purchase, int state) {
		List<String> products = purchase.getProducts();
		String productId = products.isEmpty() ? "" : products.get(0);
		String orderId   = purchase.getOrderId() != null ? purchase.getOrderId() : "";
		String token     = purchase.getPurchaseToken();
		if (purchase.getPurchaseState() == Purchase.PurchaseState.PENDING) state = STATE_PENDING;
		return new PurchaseInfo(productId, orderId, token, state);
	}

	// -------------------------------------------------------------------------
	// Static API called from C++ via JNI
	// -------------------------------------------------------------------------

	/**
	 * Sets the Base64-encoded RSA public key from Google Play Console.
	 * Location: Play Console ÔåÆ Your app ÔåÆ Monetize ÔåÆ Monetization setup ÔåÆ Licensing.
	 * Call this before any purchase; without it, signature verification is skipped.
	 */
	public static void setPublicKey(String key) {
		sPublicKey = (key != null) ? key.trim() : null;
	}

	/** Returns true; on Android, Google Play Billing is always present. */
	public static boolean isAvailable() {
		return true;
	}

	/**
	 * Asynchronously queries product details for the given IDs.
	 * Prefix a product ID with "sub:" to query as a subscription; otherwise
	 * it is queried as a one-time in-app product.
	 * Completion is delivered to C++ through nativeSetProducts().
	 */
	public static void queryProducts(String[] productIds) {
		BillingManager mgr = getInstance();
		mgr.lastError = "";
		mgr.productDetailsList.clear();
		mgr.ensureConnected(
				() -> mgr.doQueryProducts(productIds),
				() -> nativeSetProducts(new ProductInfo[0], mgr.lastError.isEmpty() ? "Billing setup failed" : mgr.lastError));
	}

	private void doQueryProducts(String[] productIds) {
		List<QueryProductDetailsParams.Product> inappList = new ArrayList<>();
		List<QueryProductDetailsParams.Product> subsList  = new ArrayList<>();
		for (String id : productIds) {
			boolean isSub   = id.startsWith("sub:");
			String  cleanId = isSub ? id.substring(4) : id;
			(isSub ? subsList : inappList).add(
					QueryProductDetailsParams.Product.newBuilder()
							.setProductId(cleanId)
							.setProductType(isSub ? BillingClient.ProductType.SUBS : BillingClient.ProductType.INAPP)
							.build());
		}

		int total = (inappList.isEmpty() ? 0 : 1) + (subsList.isEmpty() ? 0 : 1);
		if (total == 0) {
			nativeSetProducts(new ProductInfo[0], null);
			return;
		}

		AtomicInteger remaining = new AtomicInteger(total);
		ProductDetailsResponseListener listener = (result, detailsList) -> {
			if (result.getResponseCode() == BillingClient.BillingResponseCode.OK && detailsList != null) {
				synchronized (productDetailsList) {
					productDetailsList.addAll(detailsList);
				}
			} else {
				reportError(result.getDebugMessage());
			}
			if (remaining.decrementAndGet() == 0)
				nativeSetProducts(snapshotProducts(), lastError.isEmpty() ? null : lastError);
		};

		if (!inappList.isEmpty())
			billingClient.queryProductDetailsAsync(
					QueryProductDetailsParams.newBuilder().setProductList(inappList).build(), listener);
		if (!subsList.isEmpty())
			billingClient.queryProductDetailsAsync(
					QueryProductDetailsParams.newBuilder().setProductList(subsList).build(), listener);
	}

	/**
	 * Launches the Play Store billing flow for the given product ID.
	 * The product must already be in the cache from a prior queryProducts() call.
	 * Returns false if the product is not cached or billing fails to launch.
	 */
	public static boolean purchaseProduct(String productId) {
		BillingManager mgr      = getInstance();
		Activity       activity = (Activity) SDL.getContext();
		if (activity == null) {
			mgr.reportError("SDL activity not available");
			return false;
		}

		ProductDetails details = null;
		synchronized (mgr.productDetailsList) {
			for (ProductDetails pd : mgr.productDetailsList) {
				if (pd.getProductId().equals(productId)) {
					details = pd;
					break;
				}
			}
		}
		if (details == null) {
			mgr.reportError("Product not in cache: " + productId + " - call iap_query_products first");
			return false;
		}

		final ProductDetails finalDetails = details;
		mgr.activePurchaseProductId = productId;
		mgr.ensureConnected(() -> activity.runOnUiThread(() -> {
			BillingFlowParams.ProductDetailsParams.Builder pb =
					BillingFlowParams.ProductDetailsParams.newBuilder().setProductDetails(finalDetails);
			List<ProductDetails.SubscriptionOfferDetails> subs = finalDetails.getSubscriptionOfferDetails();
			if (subs != null && !subs.isEmpty())
				pb.setOfferToken(subs.get(0).getOfferToken());

			BillingFlowParams flowParams = BillingFlowParams.newBuilder()
					.setProductDetailsParamsList(Collections.singletonList(pb.build()))
					.build();
			BillingResult result = mgr.billingClient.launchBillingFlow(activity, flowParams);
			if (result.getResponseCode() != BillingClient.BillingResponseCode.OK)
				mgr.reportError(result.getDebugMessage());
		}), () -> mgr.reportError("Billing client unavailable for purchase"));
		return true;
	}

	/**
	 * Queries the Play Store for already-owned purchases and queues them as
	 * STATE_RESTORED records after fraud-checking each one.
	 */
	public static void restorePurchases() {
		BillingManager mgr = getInstance();
		mgr.lastError = "";
		Runnable doRestore = () -> {
			AtomicInteger remaining = new AtomicInteger(2);
			List<PurchaseInfo> restored = Collections.synchronizedList(new ArrayList<>());
			Runnable finish = () -> {
				if (remaining.decrementAndGet() == 0) {
					if (!restored.isEmpty())
						nativeAddPendingPurchases(restored.toArray(new PurchaseInfo[0]), null);
					nativeFinishRestore(mgr.lastError.isEmpty() ? null : mgr.lastError);
				}
			};
			mgr.billingClient.queryPurchasesAsync(
					QueryPurchasesParams.newBuilder().setProductType(BillingClient.ProductType.INAPP).build(),
					(result, purchases) -> {
						if (result.getResponseCode() == BillingClient.BillingResponseCode.OK)
							for (Purchase p : purchases) {
								String fraud = fraudCheck(p);
								if (fraud != null) { mgr.reportError(fraud); continue; }
								restored.add(mgr.buildPurchaseInfo(p, STATE_RESTORED));
							}
						else mgr.reportError(result.getDebugMessage());
						finish.run();
					});
			mgr.billingClient.queryPurchasesAsync(
					QueryPurchasesParams.newBuilder().setProductType(BillingClient.ProductType.SUBS).build(),
					(result, purchases) -> {
						if (result.getResponseCode() == BillingClient.BillingResponseCode.OK)
							for (Purchase p : purchases) {
								String fraud = fraudCheck(p);
								if (fraud != null) { mgr.reportError(fraud); continue; }
								restored.add(mgr.buildPurchaseInfo(p, STATE_RESTORED));
							}
						else mgr.reportError(result.getDebugMessage());
						finish.run();
					});
		};
		mgr.ensureConnected(doRestore, () -> nativeFinishRestore(mgr.lastError.isEmpty() ? "Billing setup failed" : mgr.lastError));
	}

	/**
	 * Acknowledges a non-consumable or subscription purchase.
	 * Must be called within 3 days of a successful purchase to avoid refund.
	 */
	public static void acknowledgePurchase(String token) {
		BillingManager mgr = getInstance();
		mgr.ensureConnected(() -> mgr.billingClient.acknowledgePurchase(
				AcknowledgePurchaseParams.newBuilder().setPurchaseToken(token).build(),
				result -> {
					boolean ok = result.getResponseCode() == BillingClient.BillingResponseCode.OK;
					if (!ok) mgr.reportError(result.getDebugMessage());
					nativeFinishOp(ok);
				}), () -> {
			mgr.reportError("Billing client unavailable for acknowledge");
			nativeFinishOp(false);
		});
	}

	/**
	 * Consumes a consumable purchase so it can be bought again.
	 */
	public static void consumePurchase(String token) {
		BillingManager mgr = getInstance();
		mgr.ensureConnected(() -> mgr.billingClient.consumeAsync(
				ConsumeParams.newBuilder().setPurchaseToken(token).build(),
				(result, purchaseToken) -> {
					boolean ok = result.getResponseCode() == BillingClient.BillingResponseCode.OK;
					if (!ok) mgr.reportError(result.getDebugMessage());
					nativeFinishOp(ok);
				}), () -> {
			mgr.reportError("Billing client unavailable for consume");
			nativeFinishOp(false);
		});
	}
}
