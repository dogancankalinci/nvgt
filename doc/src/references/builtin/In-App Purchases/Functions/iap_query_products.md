# iap_query_products
Begin an asynchronous query for the store metadata (title, description, price) of the given products.

`bool iap_query_products(string[]@ product_ids);`

## Arguments:
* string[]@ product_ids: an array of store product identifiers to look up.

## Returns:
bool: true if the query was successfully started, false if it could not be initiated.

## Remarks:
This call returns immediately; the actual lookup happens in the background. Poll iap_products_ready() until it returns true, then call iap_get_products() to retrieve the results. You must successfully query a product before you can display it or sell it with iap_purchase_product(). The identifiers must exactly match those configured in the Google Play Console or App Store Connect.
