# accessControl

`accessControl` is a Magisk module that places selected Android packages in
package-specific SELinux domains and removes configured file permissions from
those domains at boot.

It requires Android 8.0 or newer and a current Magisk build whose
`magiskpolicy` supports `--print-rules`.

## Configuration

Persistent files are created on first boot in:

```text
/data/adb/dev.accessControl/default.conf
/data/adb/dev.accessControl/target.csv
```

`target.csv` has four comma-separated fields:

```csv
package,domain,target,permissions
com.example.reader,ac_example_reader,/data/local/tmp/private.txt,read
com.example.editor,ac_example_editor,/data/local/tmp/private,read|write
```

- `package`: exact Android application ID.
- `domain`: a unique lowercase SELinux type beginning with `ac_`. One package
  must use one domain, and one domain must belong to one package.
- `target`: an existing absolute file, symlink, or directory path.
- `permissions`: one or more of `read`, `write`, `execute`, `delete`,
  `metadata`, or `all`, joined with `|`.

Use the Magisk action button to validate and reload edited rules. Logs and
generated previews are written under `/data/adb/dev.accessControl`.

`BASE_DOMAIN` in `default.conf` selects the existing application domain copied
for each custom domain. The default, `untrusted_app`, is intended for current
ordinary third-party apps. If an app normally uses a different SELinux domain,
set this value accordingly and reboot; one module configuration therefore
expects all selected packages to share the same base domain.

## Dynamic loading

There is no background watcher or polling loop. With `DYNAMIC_LOAD=1`, edit the
configuration and click the module's action button in Magisk to reload it into
the live policy. With `DYNAMIC_LOAD=0`, the action button skips reloading and
changes are applied only at the next boot.

New and stricter denies can take effect from an action reload when the package
is already running in its configured `ac_*` domain. SELinux policy removal is
not safely reversible, so deleting or relaxing a loaded rule requires a reboot.
Adding a new package mapping also requires a reboot because Zygote reads
`seapp_contexts` at startup. A missing target remains pending until the user
clicks the action button again after that target appears.

## Important SELinux scope

SELinux authorizes object *types*, not literal path strings. The module resolves
the SELinux type currently attached to `target` and denies that type to the
package-specific domain. If other paths share the same type, the selected
package is denied there too. Other packages remain in their normal domains.

The custom domain receives a copy of the selected base domain's live allow and
transition rules and also joins the common app attributes used by SELinux
constraints. Conditional vendor behavior can still differ, so privileged or
device-specific applications should be tested carefully. Invalid configuration
is rejected and the boot-time app-domain overlay is removed if policy loading
fails.

Only normal `_app` processes are remapped. Isolated processes and packages that
share an Android UID are outside the supported scope. After reboot, verify a
mapping with `ps -AZ | grep <package>` before relying on the deny rule.
