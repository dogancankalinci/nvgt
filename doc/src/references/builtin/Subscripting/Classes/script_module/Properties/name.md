# name
The name of the module.

`string script_module::name;`

## Remarks:
Changing it renames the module in the engine, so script_get_module() must then be given the new name. A name another module already has is refused with an exception.
