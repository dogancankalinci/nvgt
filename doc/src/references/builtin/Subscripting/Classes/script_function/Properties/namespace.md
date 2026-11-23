# namespace
The namespace of the function, or an empty string for the global namespace.

`const string script_function::namespace;`

## Remarks:
namespace is a reserved word of the language, so the property can't be read as `func.namespace`: call its accessor, `func.get_namespace()`.
