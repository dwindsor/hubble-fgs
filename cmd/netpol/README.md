Network policy utility
----------------------

The 'netpol' program helps checking and validating network policy changes.

Most of these commands take as argument one or two policy directories.
The policy directories should contain one or more SmartSwitchNetworkPolicy
objects in YAML format (e.g. kubectl get -o yaml).

A staging policy directory is a modified subset of the production policies,
e.g. if the production policies have been written to production/ directory,
then to start staging changes simply copy the policy files you want to test
with to staging/:

```
  $ mkdir production staging
  $ kubectl get smartswitchnetworkpolicies/http-policy -o yaml production/http-policy.yaml
  $ kubectl get smartswitchnetworkpolicies/smtp-policy -o yaml production/smtp-policy.yaml
  $ netpol print production
  $ cp production/http-policy.yaml staging/http-policy.yaml
  $ $EDITOR staging/http-policy.yaml
  $ netpol check --timescape=server:4244 production staging
```

netpol print
============

The print command prints all policies in the directory as a single table:

```
  $ netpol print production
  Rule                Proto  Src          SrcPort  SrcVLAN  SrcVRF  Dst            DstPort  DstVLAN  DstVRF  Action
  smtp/allow-smtp     TCP    0.0.0.0/0    *        1                0.0.0.0/0      25       1                allow
  ...
```


netpol convert
==============

The convert command converts policies in the table format into the SmartSwitchNetworkPolicy CRD:

```
  $ netpol convert my-policies.table
  apiVersion: isovalent.com/v1alpha1
  kind: SmartSwitchNetworkPolicy
  metadata:
    name: my-policies
  spec:
    rules:
    ...
```

netpol lint
===========

The lint command checks if there is any rules in the policies that are shadowed by a more
general rule:

```
  $ netpol lint production
  Shadowed rules
  --------------
  
    * Rule "deny-1" (deny 0.0.0.0/0 * -> 10.2.0.1/32 * TCP) is shadowed by:
      + "deny-2" (deny 0.0.0.0/0 * -> 10.2.0.0/24 * TCP)
```

netpol diff
===========

The diff command calculates the difference between the production and staging
policies and shows for which address/port ranges will we get different
verdicts:

```
  $ netpol diff production staging
  Verdict differences
  -------------------
  0.0.0.0/0:* -> 10.2.0.0/16:80
       Rule                Proto  Src          SrcPort  SrcVLAN  SrcVRF  Dst          DstPort  DstVLAN  DstVRF  Action
    -  example/allow-http  TCP    10.1.0.0/16  *        10               10.2.0.0/16  80       10               allow
    +  example/deny-1      TCP    0.0.0.0/0    *        10               10.2.0.1/32  *        10               deny
    +  example/allow-http  TCP    10.1.0.0/16  *        10               10.2.0.0/24  80       10               allow

  0.0.0.0/0:* -> 10.2.0.0/24:80
       Rule                Proto  Src          SrcPort  SrcVLAN  SrcVRF  Dst          DstPort  DstVLAN  DstVRF  Action
    -  example/allow-http  TCP    10.1.0.0/16  *        10               10.2.0.0/16  80       10               allow
    +  example/deny-1      TCP    0.0.0.0/0    *        10               10.2.0.1/32  *        10               deny
    +  example/allow-http  TCP    10.1.0.0/16  *        10               10.2.0.0/24  80       10               allow

  Old policy for affected intervals
  ---------------------------------
  
  Rule                Proto  Src          SrcPort  SrcVLAN  SrcVRF  Dst            DstPort  DstVLAN  DstVRF  Action
  example/allow-http  TCP    10.1.0.0/16  *        10               10.2.0.0/16    80       10               allow
  
  New policy for affected intervals
  ---------------------------------
  
  Rule                Proto  Src          SrcPort  SrcVLAN  SrcVRF  Dst            DstPort  DstVLAN  DstVRF  Action
  example/deny-1      TCP    0.0.0.0/0    *        10               10.2.0.1/32    *        10               deny
  example/allow-http  TCP    10.1.0.0/16  *        10               10.2.0.0/24    80       10               allow
```

The output above shows that traffic going to 10.2.0.0/16 port 80 is allowed in production policy (-), but
in staging policy (+) only traffic to 10.2.0.0/24 is allowed and 10.2.0.1/32 denied (other traffic will
hit the default deny).

netpol check
============

The check command validates a policy change against a recent matching
connections from Timescape and prints out the connections for which the
policy with the production policies did not match with staging policies:

```
  $ netpol check --timescape=server:4244 production staging
  Src           SrcPort  SrcVLAN  SrcVRF  Dst         DstPort  DstVLAN  DstVRF  Proto  Old Verdict                 New Verdict
  10.1.0.1      20       10               10.2.0.2    80       10               TCP    deny (example/deny-2)       allow (example/allow-http)
```

In the output we can see that a connection from 10.1.0.1:20->10.2.0.2:80 was denied by the production policies and
now allowed by staging policy.

The default duration to go back for connections is 10 minutes. It can be configured with "--duration", e.g.
to look at connections from last 1h: `netpol check --duration=1h production staging`.

netpol tui
==========

Text-mode user interface for comparing old and new versions of policies
with live loading of connections from Timescape that have a different verdict
between the old and new version of the policy.

The production and staging policies are analyzed to find which rules
have changed and connections matching the changed rules are then streamed
from Timescape every 10 seconds.

The UI consists of (top-to-bottom):
- The production policies that staging has modified
- The staging policies
- Updating table of connections with differing verdicts
- Connection filter prompt

The policies can be reloaded with Ctrl-R. This will reset the connections.

The connections can be filtered with a regular expression. Either the
"Filter flows" prompt at the bottom with your mouse or press Tab to
focus it. Enter the filter term as a regular expression and press enter.

Example usage: `netpol tui --timescape=server:4244 policies/production policies/staging`

netpol controller
=================

The controller command is similar to the `check` command, but performs the validation
automatically against SmartSwitchNetworkPolicies in Kubernetes that have the
`smartswitchnetworkpolicies.isovalent.com/staging` annotation set and pointing
to the policy being modified.
