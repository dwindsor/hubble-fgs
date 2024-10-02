# Tetragon Enterprise Helm chart

Tetragon Enterprise Helm chart is located in `tetragon` directory. It's
generated from:
1. Tetragon OSS Helm chart (`install/kubernetes/tetragon` in OSS submodule)
2. Enterprise extensions (`enterprise` directory)
3. Enterprise CRDs overwriting the OSS ones

## Generate the chart

To generate the chart, run:

    make

The default Makefile target will also generate the chart docs (`README.md`).

## Validate the chart

To validate the chart, run:

    make validation

This will lint the chart and validate the default ruleset policies.

## Add enterprise-only functionality

To add an enterprise-only functionality, you must first edit the `enterprise`,
directory, then generate the chart. `enterprise` directory is not a standalone
chart, and `tetragon` directory must not be edited directly.

Most of the extensions are straightforward:
- adding a new value to values.yaml
- overwriting an OSS value default or docs
- adding a new template/editing an enterprise-only template
- adding a default policy or a dashboard (both are enterprise-only)

Some enterprise-only functionalities require extending an OSS template (for
example the agent daemonset). This is achieved by adding an empty "extension"
definition in the OSS chart, then adding an actual non-empty extension in
`enterprise` directory. Such extensions are defined in `_extensions.tpl` files.
For an example see:
- OSS: https://github.com/cilium/tetragon/pull/1846
- EE: https://github.com/isovalent/hubble-fgs/pull/3734/files#diff-5006d7667036b10df4d96135af0bf2c8fe779a3d658f648a729c171feddd32d0
