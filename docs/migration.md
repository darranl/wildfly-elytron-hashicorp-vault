# Migration Guide: Legacy to New Alias Format

The upgrade criterion is that an existing `1.0.1.Final` legacy alias continues to select the same
credential when legacy support is enabled. Users can then migrate aliases individually, verify
their destinations, and disable compatibility after the migration is complete.

## Enable Compatibility Before Upgrading

The library's `support-legacy-alias-format` implementation property defaults to `false`. Set it
to `true` on each credential store that still has legacy references. This allows both legacy
aliases and explicitly marked modern aliases in that store. It does not rewrite existing aliases.

For a store configured through the Elytron provider, include this implementation property:

```xml
<property name="support-legacy-alias-format" value="true"/>
```

For a native WildFly HashiCorp Vault subsystem store, the subsystem supplies the property from
the server stability level: Community enables legacy support; Default disables it. Plan the
server stability setting as part of the upgrade. Enabling compatibility in another store does
not enable it for this one. Keep TLS, authentication, namespace, and Vault policies configured
for the intended deployment.

## Understand the Destination Before Converting

Final documented aliases include the mount:

```text
secret/myapp.database_password
```

This means mount `secret`, secret `myapp`, literal key `database_password`. It must continue to
access that destination, rather than `secret/secret/myapp` under the default mount.
A custom mount works the same way: `custom/myapp.password` selects mount `custom`.

Legacy path and key encoding differ:

- The key is a literal top-level JSON field. `/` does not traverse an object, `%20` is not a space,
  and `+`, `?`, `#`, and `@` are part of its name.
- The path followed HTTP URL semantics in Final. `%20` addresses a space, `%2520` addresses the
  literal text `%20`, and a literal `+` in the path stays a plus. Raw `?` or `#` begins a URL
  query or fragment, rather than becoming part of the secret name. Queries are preserved, including
  `?version=1` for a historical KV v2 version; fragments are excluded as in Final. Encoded `%3F` and
  `%23` remain literal path characters.
- One or more raw leading slashes are accepted; raw slash runs collapse before percent decoding. The first path component identifies the mount.
- Final required exactly one non-trailing dot. Its Java split operation discarded trailing dots,
  so `secret/app.key.` and `secret/app.key..` selected `key`. Compatibility retains this behavior.
  The later extension splitting at the last dot to allow dots in secret paths is also retained.
  A path without a slash uses the configured default mount; use the mount-qualified form when
  comparing against a Final deployment.

There is no fallback to another key or path if a literal key or secret is absent. A fallback
could silently select another credential when both interpretations exist.

## Use Explicit Modern Aliases

Prefer the fully qualified modern spelling during migration:

```text
@mount#secret-path?key-path
```

For example:

```text
secret/myapp.database_password  →  @secret#myapp?database_password
```

The explicit mount and `#` remove ambiguity and keep the destination stable with compatibility
either enabled or disabled. `#myapp?database_password` also selects the configured default mount,
which is useful when that default is intentionally part of the configuration.

For modern aliases, percent-encode literal names. A raw `/` in the key traverses nested objects;
`%2F` is a slash inside one literal field name. Each segment is decoded exactly once. `%25`
represents a literal percent sign, `%2B` a plus, and `%20` a space. Existing modern decoding and
nested traversal rules apply with either compatibility setting.

| Existing legacy alias | Modern alias for the same credential |
| --- | --- |
| `secret/myapp/db.password` | `@secret#myapp/db?password` |
| `custom/myapp.password` | `@custom#myapp?password` |
| `secret/app.database/host` | `@secret#app?database%2Fhost` |
| `secret/app.database%2Fhost` | `@secret#app?database%252Fhost` |
| `secret/app.a+b` | `@secret#app?a%2Bb` |
| `secret/app.a%20b` | `@secret#app?a%2520b` |
| `secret/app.a?b` | `@secret#app?a%3Fb` |
| `secret/app.a#b` | `@secret#app?a%23b` |
| `secret/app.a@b` | `@secret#app?a%40b` |
| `secret/app+name.key` | `@secret#app%2Bname?key` |
| `secret/app%20name.key` | `@secret#app%20name?key` |
| `secret/app%2520name.key` | `@secret#app%2520name?key` |

A nested JSON object needs a different alias from a literal slash key:

```json
{
  "database/host": "literal credential",
  "database": {"host": "nested credential"}
}
```

`@secret#app?database%2Fhost` selects the literal credential.
`@secret#app?database/host` selects the nested credential. Merely replacing the legacy dot with
`?` would change which credential is selected in this example.

## Format Precedence During Migration

An initial `#` or a complete modern header (`@mount#path?key` or `engine=TYPE[@mount]#path?key`)
selects modern parsing. A legacy mount whose name starts with `@` or `engine=` remains legacy
when the complete header is absent. With compatibility
enabled, an unprefixed dot alias takes legacy precedence, including when its literal key contains
`?`, `#`, or `@`. Otherwise a `?` separates the modern path and key.

This overlap cannot be resolved from the credential data safely. Always make modern aliases
explicit before changing the compatibility switch:

| Alias | Legacy support on | Legacy support off |
| --- | --- | --- |
| `secret/app.a?b` | Mount `secret`, secret `app`, literal key `a?b` | Default mount, secret `secret/app.a`, key `b` |
| `myapp/db?password` | Mount `myapp`, secret `db`, key `password` | Default mount, secret `myapp/db`, key `password` |
| `#myapp/db?password` | Default mount, secret `myapp/db`, key `password` | Same |
| `@secret#app?a%3Fb` | Mount `secret`, secret `app`, literal key `a?b` | Same |

The fully qualified modern prefix is reserved for the modern grammar. Use explicit modern aliases
for any unusual legacy spelling that collides with it. Turning compatibility off is not a migration
validator: an ambiguous alias may remain syntactically valid while addressing a different secret.

## Legacy Object Credentials

Final returned a top-level JSON object as serialized JSON credential text. Legacy aliases and the
deprecated path/key constructor retain that behavior, including the original member types and nulls.
Arrays, numbers, and booleans also retain their JSON text representation.

Modern aliases require a leaf credential. An alias pointing to a whole object returns no credential;
use a nested key path to select a leaf inside it. Legacy object-text results are not cached in the
shared scalar credential cache, so they cannot make an equivalent modern container alias return text.

If an application requires the whole JSON document as its password, preserve that document as a JSON
**string** field before converting the reference to modern syntax. Plan and verify that schema change
separately. Replacing the dot with `?` cannot preserve an object-as-text credential by itself.

## Legacy HTTP Queries

A legacy alias such as `secret/app?version=1.password` selects the historical KV v2 version 1,
not the latest credential. Compatibility preserves that query for reads and for the read/update
operations used by writes and removals. A query-based write can create a new latest version from
historical data; this matches Final's target behavior. Verify the intended version before mutation.

The modern alias format cannot express HTTP query parameters. A query alias emits a dedicated
warning rather than suggesting an equivalent modern alias that would lose version selection.
Keep compatibility enabled for these references until version pinning is no longer required or
an appropriate replacement is available. Simply changing this example to `@secret#app?password`
would select the latest version. Queries are not cached as unversioned credentials.

## Legacy Literal Keys and Release Candidate Compatibility

`1.1.0.CR1` through `1.1.0.CR3` decoded legacy keys and interpreted `/` as nested traversal.
They could also prefix the configured default mount again for a dot alias. Those behaviors differ
from Final and are not the compatibility target. If a configuration deliberately relied on a
release candidate's interpretation, convert it to an explicit modern alias for that destination
before adopting restored Final compatibility.

For example, under default mount `secret`:

- If `app.database/host` intentionally selected a nested value in those releases, use
  `@secret#app?database/host`. To select Final's literal field, use `@secret#app?database%2Fhost`.
- If `app.a+b` or `app.a%20b` intentionally selected key `a b`, use `@secret#app?a%20b`.
  Final's literal keys instead require `%2B` or `%2520`, respectively.
- If `secret/app.key` intentionally accessed secret `secret/app` within mount `secret` because
  of the duplicate prefix, use `@secret#secret/app?key`. The Final destination is `@secret#app?key`.

Warnings and rejection messages now suggest the equivalent alias for the restored Final destination.
Compare the mount, secret, and key with the deployment's intended data before applying a suggestion.

## Java Credential Sources

The deprecated constructor `VaultCredentialSource(connector, secretPath, secretKey)` preserves
Final's mount-qualified wire path and literal key behavior independently of the store switch.
For example, path `secret/app%20name` selects `app name`, and key `database/host` is literal.

The alias-string constructor accepts modern syntax only. Use an explicit modern alias from the
table above. The constructor taking explicit engine, mount, secret, and key-path components expects
decoded component names; its key path still uses `/` for traversal. Do not percent-encode decoded
components when using that constructor.

## Roll Out and Verify

1. Enable compatibility for every store with legacy references before upgrading the library.
2. In a test deployment, verify unchanged credential references against known Vault destinations.
   Include custom mounts and any keys or paths containing special characters.
3. Convert references one at a time to explicit modern aliases, preserving the original mount,
   path, and literal key. Verify the application uses the intended credential after each change.
4. Check all references, including expressions, data sources, LDAP configuration, and scripts.
   Exercise reload or restart so successful reads are not solely cached results.
5. Resolve any references that require legacy query parameters before disabling compatibility.
   Disable compatibility after all aliases are explicit modern forms. Verify the same application
   behavior again. Retain the previous configuration for the deployment's rollback procedure.

Migration does not require moving Vault data or rewriting fields into nested objects. If a secret
schema change is desired, plan it separately from changing alias syntax.

See the [complete alias reference](alias-format.md) for engine selection, listing, escaping, and
nested key operations.
