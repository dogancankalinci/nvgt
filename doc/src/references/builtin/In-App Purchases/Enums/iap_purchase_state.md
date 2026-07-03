# iap_purchase_state
This enum describes the outcome of an in-app purchase transaction. It is returned by the `iap_purchase` class's `state` property.

## Constants:
* IAP_PURCHASE_SUCCESS: the purchase completed successfully and the item should be granted to the player.
* IAP_PURCHASE_CANCELLED: the user cancelled the purchase before it completed.
* IAP_PURCHASE_FAILED: the purchase failed. This is also the default state used when something goes wrong; call iap_get_last_error() for details.
* IAP_PURCHASE_RESTORED: a product the user previously owned was restored (see iap_restore_purchases). Treat this like a success for granting non-consumable items.
* IAP_PURCHASE_PENDING: the purchase is pending, for example while awaiting an external or delayed payment method.
* IAP_PURCHASE_DEFERRED: the purchase is deferred, for example while awaiting parental approval (Apple's Ask to Buy). Do not grant the item until it later completes.
