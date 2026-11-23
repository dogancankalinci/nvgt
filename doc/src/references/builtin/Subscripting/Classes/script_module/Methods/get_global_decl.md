# get_global_decl
Get the declaration of a global variable of the module.

`const string script_module::get_global_decl(uint index);`

## Arguments:
* uint index: the index of the global.

## Returns:
const string: the declaration, such as `int counter`, with the namespace of a global declared in one (`int game::counter`), or an empty string if the index is out of range.
