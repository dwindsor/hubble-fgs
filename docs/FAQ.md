# Tetragon FAQ

## Development

### When does the OSS tetragon code get synced to EE (isovalent/hubble-fgs)? Is it periodic or is it the responsibility of the developer?

It's the responsibility of the developer. We call this process an "OSS sync".

To do an OSS sync:
1. Check if someone has announced that they are doing an OSS sync in #vertical-tetragon
1. rebase your EE branch against latest master to pick any other OSS syncs someone else might have
   started
1. run `make oss-sync` and commit the changes in a separate commit (chore: oss-sync)
1. if anything from OSS has broken the build, you will need to fix it or track down the original author of the corresponding change and ask them to port the changes
1. Push a PR and mention it in #vertical-tetragon so that folk are aware than an OSS sync is in
   progress

For OSS PRs that might cause EE breakage, it's a good practice to mark your OSS PRs as draft and do
a test OSS sync PR (there is a script for that: `contrib/oss-chores/oss-pr-sync.sh`), where any
issues are resolved before the OSS PR is merged. This processes adds friction but it saves a
significant amount of long term pain from merging something in OSS that breaks EE and only finding
out later. Reverting OSS changes because they break EE is very awkward and we should avoid it.

Reviewers of OSS PRs that suspect that the OSS PR will cause issues in EE should ask isovalent
developers to do a test OSS sync PR (#vertical-tetragon is a good place for these discussions) as
described above. For PRs submitted by non-isovalent developers, reviewers are encouraged to notify
owners of the code that may be affected.

### What to do if LVH dep update fails?

When the LVH dependency updates, the `kvm-gotests` workflow may start
failing for newer kernel updates. Here's how to handle these failures:

**1. Find the failing test**

Open the failed job logs and look at the "Provision LVH VM and run tests" step.
The output will contain lines like:

```
--- FAIL: TestSomeTestName (300.29s)
```

Note the test name.

**2. Find who wrote the test**

You can use `git blame` in your IDE or the GitHub UI to find the author.
From the command line, `git grep` + `git annotate` also works:

```
$ git grep -n TestSomeTestName 
pkg/sensors/some_file_test.go:100:func TestSomeTestName(t *testing.T) {

$ git annotate -L 100,+10 pkg/sensors/some_file_test.go
```

**3. Notify and discuss**

Create a thread in `#vertical-tetragon` mentioning the failing test, and
CC the test author. Ask them whether they want to investigate or if 
the test should be temporarily disabled.

**4. Disable the test if needed**

If the test is broken and a fix is not immediately available, disable it
with a version check and a `t.Skip`. For example:

```go
func TestSomeTestName(t *testing.T) {
	if IsKernelVersionGreaterThan("6.19") {
		t.Skip("This test does not work for 6.19 onwards. Disabled.")
	}
	// ...
}
```
### How do build things on my laptop that depend on artifactory images?

For example, `make image` may lead to errors such as:

```
ERROR: failed to build: failed to solve: failed to fetch anonymous token: unexpected status from GET request to https://artifactory.devhub-cloud.cisco.com/v2/token?scope=repository%3Aglibc-openssl%3Apull&scope=repository%3Asto-cg-docker%2Fglibc-openssl%3Apull&service=artifactory.devhub-cloud.cisco.com: 401 Unauthorized
```

To solve this issue, you need access to
https://artifactory.devhub-cloud.cisco.com/ui/repos/tree/General/sto-cg-docker.

Then you need to create a token. To do so, follow the instructions under "How Do I Create An Access
Token Via The UI?" in
https://code.cisco.com/code-docs/dev-tools/binary/platform-offerings/artifactory/faq

Once you have a token, you can use it as a password to login to artifactory.devhub-cloud.cisco.com:
```
docker login artifactory.devhub-cloud.cisco.com -u <username>
```

Where <username> is your cisco username.

See slack thread: https://isovalent.slack.com/archives/C01N6G0CHFV/p1779266912678339

## Alerts

### Can I use CEL to filter all events based on process information?

You can use a `filter` expression over all the event types that are you are interested in.
For example:
```
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: test
spec:
  expression: >
    [process_exec, process_exit, process_kprobe, process_tracepoint, process_connect].filter(
      ev, ev.process.binary == "/usr/bin/dash"
    ).size() > 0
  message: test
  severity: info
  tags: []
```
