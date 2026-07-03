# iap_restore_purchases
Begin restoring the user's previously owned purchases.

`bool iap_restore_purchases();`

## Returns:
bool: true if the restore operation was successfully started, false otherwise.

## Remarks:
Use this to let players recover non-consumable purchases and subscriptions they already own, for example after reinstalling your game or switching devices. The operation is asynchronous: poll iap_restore_finished() until it returns true, then collect the restored items from iap_get_pending_purchases(), where they arrive with a state of IAP_PURCHASE_RESTORED. Apple's guidelines require you to provide a visible "Restore Purchases" option in apps that sell non-consumable products.
