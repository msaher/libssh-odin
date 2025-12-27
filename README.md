# Libssh Odin bindings

Odin bindings for <https://www.libssh.org/>

Don't forget to modify `foreign import` and link the other libraries libssh needs. For example:

```odin
foreign import ssh {
    "./libssh.a",
    "system:ssl",
    "system:crypto",
    "system:gssapi_krb5",
    "system:z",
}
```
