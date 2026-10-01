# Java runtime patching through JVM Attach

The `spec.java` policy extension applies complete Java class-file replacements
to an already-running HotSpot JVM. Tetragon speaks the Linux HotSpot Attach
socket protocol directly; it does not start a Java helper or require JDWP to be
enabled. The Attach `load` operation loads the packaged native JVMTI library,
which calls `RedefineClasses` in the target VM. The native library is not a Java
agent JAR.

The agent is built from `pkg/sensors/java/agent/jvm_patch.c` with OpenJDK
headers by `make tetragon-java-patch-agent`. Container and tarball builds place
`libtetragon-jvm-patch.so` beside the Tetragon runtime assets in its configured
library directory. It must match the target architecture and libc. The policy
lists exact executable paths and can require argument fragments to scope
attachment to one Java service. Tetragon records host PIDs but uses the
innermost PID from `/proc/<pid>/status` for `.attach_pid*` and `.java_pid*`
inside a PID namespace.

Each patch carries two base64-encoded complete `.class` files:

- `replacement`: the fixed class installed when the policy loads.
- `rollback`: the original class restored when the policy unloads.

Both files must define the signature named in `signature`. Standard HotSpot
class redefinition cannot add/remove fields or methods or change class
hierarchy/modifiers. It also cannot update active stack frames; already-running
calls finish with the old bytecode while later calls use the replacement.

Tetragon stages the native library and mode-0600 manifests in the target JVM's
own mount namespace under `/run/tetragon-java-patch`, in a mode-0700 directory
owned by that JVM's user. It then invokes Attach `load` with namespace-visible
paths. This supports product processes running in separate mount namespaces.
Tetragon emits structured log records with the JVM PID, class signature, and
tracing-policy name for apply and rollback. The records contain no class bytes
or application arguments. Unloading the policy sends the rollback manifest to
every still-running JVM previously patched by that policy.

The VM's Attach mechanism must be enabled, the target JVM must be HotSpot with
JVMTI class redefinition support, and the Tetragon process must have permission
to create the Attach trigger and connect to the target. A missing Attach
listener is started using HotSpot's namespace-local `.attach_pid` trigger and
`SIGQUIT` flow.
After load, the sensor scans `/proc` once per second and applies the patch to
new matching JVMs. It retries failed attaches while a process remains alive,
which lets the target application finish loading the selected class. Policy
unload stops reconciliation, restores every still-running patched JVM, and
removes its staged files.

See `examples/tracingpolicy/java-patch-template.yaml` for the policy shape.
