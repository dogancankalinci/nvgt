# iap_get_products
Retrieve the list of products whose metadata was fetched by a completed iap_query_products() call.

`iap_product@[]@ iap_get_products();`

## Returns:
iap_product@[]@: an array of `iap_product` handles describing each successfully queried product.

## Remarks:
Only call this once iap_products_ready() returns true. The returned array reflects the most recent successful query; products whose identifiers were not recognized by the store will simply be absent. Use each product's title, description, and price properties to build your store interface.
