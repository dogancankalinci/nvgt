# iap_products_ready
Check whether the product query started with iap_query_products() has finished and its results are ready.

`bool iap_products_ready();`

## Returns:
bool: true once queried product metadata is available, false while the query is still in progress.

## Remarks:
This is the polling companion to iap_query_products(). Call it each frame after starting a query; when it returns true, call iap_get_products() to read the product list.
