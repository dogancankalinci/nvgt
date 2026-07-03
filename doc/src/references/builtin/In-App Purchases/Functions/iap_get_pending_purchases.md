# iap_get_pending_purchases
Retrieve and clear the queue of purchase results that have arrived since the last call.

`iap_purchase@[]@ iap_get_pending_purchases();`

## Returns:
iap_purchase@[]@: an array of `iap_purchase` handles representing transactions that completed (successfully or not) since you last called this function. The array is empty if nothing new has happened.

## Remarks:
This is a **draining** call: each time you call it, the internal queue is emptied, so a given purchase is returned exactly once. Because of this, call it regularly (typically once per frame in your game loop) and process every purchase you receive, rather than calling it repeatedly expecting the same results.

For each returned purchase, inspect its state. On IAP_PURCHASE_SUCCESS or IAP_PURCHASE_RESTORED, grant the item to the player and then finalize the transaction on Android by calling the purchase's consume() (consumables) or acknowledge() (non-consumables and subscriptions). Results here include purchases from iap_purchase_product() as well as items recovered by iap_restore_purchases().
