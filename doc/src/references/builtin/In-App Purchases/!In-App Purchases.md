# In-App Purchases
NVGT provides a small, cross-platform in-app purchase (IAP) API that lets your game sell digital products through the underlying app store: Google Play billing on Android and StoreKit on Apple platforms. The same script code works on every supported platform; NVGT talks to the correct store behind the scenes.

The API is deliberately simple and **poll based**. You never register a callback function. Instead, you kick off an asynchronous operation (querying products, making a purchase, restoring purchases) and then check back each frame with a small "is it ready yet?" function, retrieving results when they are available. This fits naturally into a normal game loop and avoids the complexity of threads or callbacks in your scripts.

## Products versus purchases
Two object types represent the two halves of a transaction:

* An `iap_product` describes something offered for sale in the store: its identifier, localized title and description, and formatted price. You must query products before you can display or sell them.
* An `iap_purchase` represents the result of an actual transaction: which product was bought, its transaction id, and its state. On Android a successful purchase must be finalized by calling either `consume()` (for consumable products that can be bought again, like a pack of coins) or `acknowledge()` (for non-consumables and subscriptions); if you do not, the store will automatically refund the purchase after a few days.

## Typical flow
1. Call `iap_available()` to make sure billing works on this device.
2. On Android, call `iap_set_android_public_key()` with your license key before doing anything else.
3. Call `iap_query_products()` with the list of product ids you sell, then poll `iap_products_ready()` until it returns true and read the results with `iap_get_products()`.
4. To sell something, call `iap_purchase_product()` with a product id (it must be one of the ids you already queried).
5. Every frame, drain any completed transactions with `iap_get_pending_purchases()` and act on each one, finalizing successful Android purchases with `consume()` or `acknowledge()`.
6. To let users recover past non-consumable purchases (for example after reinstalling), call `iap_restore_purchases()`, poll `iap_restore_finished()`, and collect the restored items from `iap_get_pending_purchases()`.
7. If any operation reports failure, call `iap_get_last_error()` for a human-readable message.

## Example
```
void main() {
	if (!iap_available()) {
		alert("Store", "In-app purchases are not available on this device.");
		return;
	}
	// On Android only, set your Google Play license key first:
	// iap_set_android_public_key("MIIBIjANBgkqh... (from the Play Console)");

	// Ask the store about the products we sell.
	string[] ids = {"com.mygame.remove_ads", "com.mygame.coins_100"};
	iap_query_products(ids);
	while (!iap_products_ready()) wait(50); // In a real game, do this in your loop instead of blocking.

	iap_product@[]@ products = iap_get_products();
	for (uint i = 0; i < products.length(); i++)
		screen_reader_speak(products[i].title + ", " + products[i].price, false);

	// Buy one of them.
	iap_purchase_product("com.mygame.remove_ads");

	// Poll for the result. A real game would do this each frame as part of its main loop.
	bool done = false;
	while (!done) {
		iap_purchase@[]@ pending = iap_get_pending_purchases(); // Draining call: empties the queue each time.
		for (uint i = 0; i < pending.length(); i++) {
			iap_purchase@ p = pending[i];
			if (p.state == IAP_PURCHASE_SUCCESS || p.state == IAP_PURCHASE_RESTORED) {
				// Grant the purchased item to the player here, then finalize the transaction:
				p.acknowledge(); // Use consume() instead for consumable products.
				done = true;
			} else if (p.state == IAP_PURCHASE_CANCELLED || p.state == IAP_PURCHASE_FAILED) {
				alert("Store", "Purchase failed: " + iap_get_last_error());
				done = true;
			}
		}
		wait(50);
	}
}
```

## Remarks
Setting up products, prices, license keys, and test accounts is done in the Google Play Console and App Store Connect, not in NVGT. You must also give your app the correct product identifier and (on Android) build with the IAP-enabled stub. Because store behavior differs between platforms, always test real purchases on real devices with store sandbox/test accounts before shipping.
