Krabs Readme.txt



Important Preprocessor Definitions:



* NDEBUG - Set this varible in release builds to disable runtime type assertions.

You'll still get a runtime error if the size type you're requesting is not the

same size as the property in the event schema.



* TYPEASSERT - Set this variable only in debug builds (not NDEBUG) to enable strict assertions.

This means that if an explicit type check is not defined for a requested type, a static_assert

is thrown and the code will not compile until one is added. This is mainly used for krabs

development to ensure that we don't miss asserts for types that are supported.