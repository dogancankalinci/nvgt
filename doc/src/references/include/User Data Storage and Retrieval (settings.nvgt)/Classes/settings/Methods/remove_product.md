# remove_product
This method removes the current product.

`bool settings::remove_product();`

## Returns:
bool: true on success, false on failure

## Remarks:
This method deletes the current product's directory and everything in it. The company directory is then deleted too if nothing is left in it (the company had no other products); one that still holds anything, such as another product's directory, is kept.
