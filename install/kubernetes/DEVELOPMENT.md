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

Chart generation and validation use the Helm 4 container pinned in the
chart Makefile, so they do not depend on a host Helm installation.

## Test the chart with Kind or e2e

The root `kind-install-tetragon` and `e2e-test` targets invoke Helm from the
host. Install Helm 4 as `helm` on `PATH` before running either target:

    helm version --short

The root Makefile rejects missing or different Helm versions before invoking
the install or e2e tooling.

## Upgrade and roll back existing releases

Helm 4 can manage releases created by Helm 3 without a separate release-state
migration. New Helm 4 releases use server-side apply by default. Upgrades and
rollbacks keep the apply method recorded by the previous release, so a release
created by Helm 3 continues to use client-side apply unless `--server-side` is
set explicitly.

When validating a migration, create the release with Helm 3, upgrade it with
Helm 4, and roll it back to the previous revision. Use
`--server-side=false` when the test must explicitly preserve Helm 3's
client-side apply behavior.

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

## Update dependencies (subcharts)

Tetragon Enterprise Helm chart includes third-party charts as dependencies.
To prevent unnecessarily fetching subcharts on every `make` run, they are
cached in `enterprise/charts` directory and copied over to `tetragon/charts`
when generating the chart - however, none of these directories are committed to
the repository.

The subchart versions are automatically updated by Renovate. After a version
update, subcharts must be re-fetched by:

    rm -rf enterprise/charts
    make tetragon/charts
