# set_size
Change the size of the font.

`bool text_font::set_size(float ptsize);`

## Arguments:
* float ptsize: the new size in points.

## Returns:
bool: true on success, false otherwise.

## Remarks:
Fonts from get_font() are shared, so changing them changes them for everything using them. Use a font of a different size from get_font() instead, or create one with allow_caching set to false.

A size larger than the font engine can render, more than 65535 pixels per em at the font's resolution (the size in points times the resolution in dots per inch, divided by 72), is refused, as a size that isn't a finite number above 0 is.
