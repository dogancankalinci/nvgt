# iap_purchase_product
Begin purchasing the product with the given identifier.

`bool iap_purchase_product(const string&in product_id);`

## Arguments:
* const string&in product_id: the identifier of the product to buy. It must be one of the products you have already successfully queried with iap_query_products().

## Returns:
bool: true if the purchase flow was successfully started, false if it could not be initiated (for example if the product id was not among the queried products).

## Remarks:
This starts the store's purchase interface and returns immediately; the transaction completes asynchronously. Watch for the result by polling iap_get_pending_purchases(), then inspect each returned purchase's state. Remember that on Android a successful purchase must be finalized with the purchase's consume() or acknowledge() method.
