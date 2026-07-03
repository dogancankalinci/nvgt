# iap_purchase
This class represents the result of an in-app purchase transaction, as returned by iap_get_pending_purchases(). You never construct one yourself; you receive them from the store when a purchase or restore completes. Its properties are read-only, but it also provides two methods used to finalize a purchase on Android.

## Properties

### product_id
The store identifier of the product that was purchased.

`const string product_id;`

### transaction_id
The store-assigned transaction identifier for this purchase. Useful for logging, receipts, or server-side validation.

`const string transaction_id;`

### state
The outcome of the transaction, as an `iap_purchase_state` value. Inspect this to decide whether to grant the item.

`const iap_purchase_state state;`

### is_pending
A convenience flag that is true when the purchase is not yet final, that is when its state is IAP_PURCHASE_PENDING or IAP_PURCHASE_DEFERRED. Do not grant the purchased item while this is true.

`const bool is_pending;`

## Methods

### consume
Finalizes a **consumable** purchase (one the player can buy again, such as a pack of coins), telling the store to mark it as used so it can be purchased again in the future.

`bool consume();`

#### Returns:
bool: true if the request to consume the purchase was submitted successfully.

#### Remarks:
This is primarily meaningful on Android. On Android you must finalize every successful purchase by calling either consume() (for consumables) or acknowledge() (for everything else); if you do not, Google Play automatically refunds the purchase after a few days.

### acknowledge
Finalizes a **non-consumable** purchase or subscription (one the player owns permanently, such as removing ads or unlocking a feature), telling the store the purchase has been recorded by your app.

`bool acknowledge();`

#### Returns:
bool: true if the request to acknowledge the purchase was submitted successfully.

#### Remarks:
This is primarily meaningful on Android, where acknowledging (or consuming) a purchase is mandatory to avoid an automatic refund. Call acknowledge() for products the user should keep, and consume() for products they can buy repeatedly.
