# iap_product
This class describes a single product offered for sale through the app store, as returned by iap_get_products(). It is a read-only snapshot of the product's store metadata; you never construct one yourself, you obtain them from the store after querying. All members are read-only property accessors.

## Properties

### product_id
The store identifier of this product, matching one of the ids you passed to iap_query_products().

`const string product_id;`

### title
The localized, human-friendly name of the product as configured in the store.

`const string title;`

### description
The localized product description as configured in the store.

`const string description;`

### price
The price already formatted for display in the user's local currency, for example "$0.99". Always show this string to users rather than building your own price text, because it is correctly localized and formatted by the store.

`const string price;`

### currency_code
The ISO currency code that the price is expressed in, for example "USD".

`const string currency_code;`

### price_micros
The raw price expressed in micro-units, that is the price multiplied by 1,000,000, as a double. This is useful for analytics or calculations; for anything shown to the user, prefer the price property.

`const double price_micros;`
