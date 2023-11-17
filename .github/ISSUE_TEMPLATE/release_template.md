---
name: Release a new version of Tetragon Enteprise
about: Create a checklist for an upcoming release
title: 'vX.Y.Z release'
labels: kind/release
assignees: ''
---

## Tetragon Enterprise release checklist

The following is a release checklist that should be followed when cutting a new release of Tetragon Enterprise. Please follow the steps carefully and ask for help in Slack if you have difficulty during the release process.

### Minor Version Bump

If you are doing a minor version bump (i.e. the Y in X.Y.Z), there are a few steps we need to do first before we can work on the Enterprise release.

- [ ] [Cut a new OSS release][oss-release]
- [ ] **After** checking out your new release branch (see below) but **before** you push the tag, update the `modules/tetragon-oss` to point to your new OSS release branch, and do an OSS sync
- [ ] Make sure you add the `-rc1` suffix to the version number for release candidates (rc)

Branch `X.Y` may not exist, because we have not branched out yet. This can only happen for
`X.Y.0-rc.N` or `X.Y.0` releases. In this case:

   * If release is `X.Y.0`:
       * Create `X.Y` branch
   * Else: # release is `X.Y.0-rc.N`
       * If `N == 1`, no need to create a branch
       * If `N > 1`
           * do `git log X.Y.0-rc.N-1..master`
                * If there are non-safe commits that may introduce new bugs:
                     * Create `X.Y` branch
                     * Backport safe commits from master to `X.Y`

See [tagging] for more details.

If you create a `X.Y` branch:
 - Create a "starting `X.Y+1` development" PR on the master branch with the following changes:
    - update [CustomResourceDefinitionSchemaVersion](https://github.com/isovalent/hubble-fgs/blob/c6d2699d9d1829a2ea6a6276d410da22fef71629/pkg/k8s/apis/cilium.io/v1alpha1/version.go#L21) to `X.Y+1.0`.
 - Once PR is merged, tag the first commit in master which is not in the `X.Y` branch as
   `vX.Y+1.0-pre.0`.

### Cutting the Tetragon Enterprise release

- [ ] Check that there are no [release blockers].
- [ ] Set `RELEASE` environment variable. For example, if you are releasing `v1.9.0`:
  ```
  export RELEASE=v1.9.0
  ```
- [ ] Open a pull request to update the Helm chart version:
  ```
  git checkout -b pr/prepare-$RELEASE
  ./modules/tetragon-oss/contrib/update-helm-chart.sh $RELEASE
  ./install/kubernetes/test.sh
  git add install/kubernetes/
  git commit -s -m "Prepare for $RELEASE release"
  git push origin HEAD
  ```
- [ ] Set the `BRANCH` environment variable to the major/minor version branch. For example, if you are releasing `v1.9.0`:
  ```
  export BRANCH=v1.9
  ```
- [ ] Check that there are no open PRs (that need to be urgently merged) targeting `$BRANCH`
  ```
  xdg-open "https://github.com/isovalent/hubble-fgs/pulls?q=is%3Apr+is%3Aopen+base%3A$BRANCH"
  ```
- [ ] Create the release tags (a "main" tag, and an "api" tag):
  ```
  git checkout $BRANCH && git pull origin $BRANCH
  git tag -a "$RELEASE" -m "$RELEASE release" -s
  git tag -a "api/$RELEASE" -m "api/$RELEASE release" -s
  git push origin "$RELEASE"
  git push origin "api/$RELEASE"
  ```
- [ ] Only for major release, update `.github/renovate.json5` to include the new stable branch and remove the unsupported branch.
- [ ] Generate [release notes][hubble-fgs release] for the new release
  - [ ] Find the "main" release tag you generated
  - [ ] Click "generate release notes"
  - [ ] Click "publish release"

### Deploy the new release to tetragon-dev

- [ ] Navigate to the [cilium-enterprise-dogfooding] repo and file a PR to update the Tetragon Enterprise version in tetragon-dev
  - [ ] Edit the `infra/df-tetragon-dev-ce-01/apps/tetragon/kustomization.yaml` file and change the Helm chart version.
  - [ ] If the `infra/df-tetragon-dev-ce-01/apps/tetragon/values.yaml` file overwrites the agent or operator image, remove the overwrite.
  - [ ] Make sure that the `infra/df-tetragon-dev-ce-01/apps/tracing-policies/templates/` directory contains relevant TracingPolicies.
- [ ] Merge the PR and wait for the new release to be deployed.

### Validate the new release in tetragon-dev

- [ ] Check that all Tetragon pods are up and running. Refer to the [cilium-enterprise-dogfooding] README for the access instructions.
- [ ] Check the [Tetragon Health](https://grafana.dev.tetragon.isovalent.com/d/f4589e8b-6b8b-4431-9a8a-82616810d76b/tetragon-health) dashboard in Grafana
  - [ ] error logs
  - [ ] resources usage
  - [ ] any suspicious patterns
- [ ] Check in Grafana if Timescape is ingesting Tetragon events: [Timescape Ingestion](https://grafana.dev.tetragon.isovalent.com/d/XDyOH21Vk/timescape-ingestion). TODO: link a dashboard specific to Tetragon events.
- [ ] Check in Hubble UI if the [Process Ancestry Tree](https://hubble-ui.dev.tetragon.isovalent.com/ps-tree) is rendered correctly. Select a few sample namespaces/pods.
- [ ] Check in Hubble UI if the [Service Map](https://hubble-ui.dev.tetragon.isovalent.com/service-map) is rendered correctly. Uncheck the "Live View" toggle (this enables the Timescape mode) and select a few sample namespaces.
- [ ] Check in Grafana Timescape queries for Tetragon events: [Timescape Queries](https://grafana.dev.tetragon.isovalent.com/d/8v3KZJ14k/timescape-server). TODO: link a dashboard specific to Tetragon events.

Issues found when validating the release in tetragon-dev might not block the release, but should be communicated and documented.

**IF YOU ARE DOING A RELEASE CANDIDATE, STOP HERE.**

### Documentation

- [ ] Navigate to the [cilium-enterprise-docs] and start working on a PR to document the new release of Tetragon Enterprise.
  Check out a new release branch:
  ```
  git checkout master && git pull origin master
  git checkout -b pr/document-fgs-$RELEASE
  ```
- [ ] Add release notes to the docs
  - [ ] Edit `docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst` to add a new entry for the new version of `hubble-enterprise`. NOTE: as before, this is the version of the Helm chart, **NOT** the Tetragon Enterprise version. Example diff:
    ```diff
    diff --git a/docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst b/docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst
    index 98284b7..92a1d34 100644
    --- a/docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst
    +++ b/docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst
    @@ -4,6 +4,7 @@ Release Notes - Hubble Enterprise
     .. toctree::
       :maxdepth: 1

    +  v1.9.3
       v1.9.2
       v1.9.1
       v1.9.0
    ```
   - [ ] Create a new file `docs/operations-guide/releases/release-notes/hubble-enterprise/$RELEASE.md`. Use the release notes you generated for the `hubble-enterprise` chart as a basis for what goes into the file. You can use the following as a template:
     ```markdown
     # vX.Y.Z

     ## Features
     * Features here

     ## Enhancements
     * Update to hubble-fgs vX.Y.Z
     * Other enhancements here

     ## Breaking changes
     * Breaking changes here
     ```
- [ ] If there are any new features introduced, list them under the "Cilium Enterprise Feature Maturity List"
  - [ ] See `docs/operations-guide/features/status.rst`
- [ ] Ping feature owners to add documentation for undocumented new features
- [ ] Document any breakages in `docs/operations-guide/upgrades/tetragon-version-notes.rst` if applicable

### Updating the hubble-enterprise helm chart

- [ ] Navigate to the [hubble-enterprise chart] repo and file a PR to update the Helm chart version
  - [ ] Check out a new release branch:
    ```
    git checkout master && git pull origin master
    git checkout -b pr/prepare-fgs-$RELEASE
    ```
  - [ ] Update `values.yaml` and change the `hubble-enterprise` and `hubble-enterprise-operator` image `tag` values to the new "main" release tag. Example diff:
    ```diff
    diff --git a/values.yaml b/values.yaml
    index 85166d0..f86ba0e 100644
    --- a/values.yaml
    +++ b/values.yaml
    @@ -61,7 +61,7 @@ enterprise:
       image:
         override: ~
         repository: quay.io/isovalent/hubble-enterprise
    -    tag: v1.8.5
    +    tag: v1.9.0
       metadataImage:
         override: ~
         repository: quay.io/isovalent/hubble-enterprise-metadata
    @@ -182,7 +182,7 @@ hubbleEnterpriseOperator:
       image:
         override: ~
         repository: quay.io/isovalent/hubble-enterprise-operator
    -    tag: v1.8.5
    +    tag: v1.9.0
         # hubble-enterprise-operator image-digest
         suffix: ""
    ```
  - [ ] Run `test.sh` to generate new documentation and verify that there are no issues in the Helm templating. Ensure that the script executes without any failures:
    ```
    ./test.sh
    ```
  - [ ] Add and commit the results and file a pull request on [GitHub][hubble-enterprise chart] (HINT: you can just click the link in the output of the `git push` command):
    ```
    git commit -a -m "Prepare for $RELEASE Tetragon Enterprise release" -s && git push origin HEAD
    ```
  - [ ] After your PR is merged, tag a [new release][hubble-enterprise chart release] of `hubble-enterprise-chart`.
    - [ ] Click "generate release notes" and create a new tag with the appropriate version bump
    - [ ] NOTE: The hubble-enterprise-chart version is not strictly in lockstep with the Tetragon Enterprise version, so don't worry if they don't match
    - [ ] Click "publish release"

### Updating the umbrella chart

- [ ] Navigate to the [umbrella chart] and file a PR to update the hubble-enterprise version
  - [ ] Check out a new release branch:
    ```
    git checkout master && git pull origin master
    git checkout -b pr/pick-up-latest-hubble-enterprise
    ```
  - [ ] Edit `cilium-enterprise/Chart.yaml` to bump the hubble-enterprise version. IMPORTANT NOTE: this should be the version of the `hubble-enterprise-chart` that you released in the previous step, **NOT** the version of Tetragon Enterprise. Example diff:
    ```diff
    diff --git a/cilium-enterprise/Chart.yaml b/cilium-enterprise/Chart.yaml
    index ffcacbe..ee663d9 100644
    --- a/cilium-enterprise/Chart.yaml
    +++ b/cilium-enterprise/Chart.yaml
    @@ -26,7 +26,7 @@ dependencies:
       repository: "https://helm.isovalent.com"
       condition: cilium.enabled
     - name: hubble-enterprise
    -  version: "1.9.2"
    +  version: "1.9.3"
       repository: "https://helm.isovalent.com"
       condition: hubble-enterprise.enabled
     - name: hubble-ui
    ```
  - [ ] Run `test.sh` to generate new documentation and verify that there are no issues in the Helm templating. Ensure that the script executes without any failures:
    ```
    ./test.sh
    ```
  - [ ] Add and commit the results and file a pull request on [GitHub][umbrella chart] (HINT: you can just click the link in the output of the `git push` command):
    ```
    git commit -a -m "Pick up latest hubble-enterprise" -s && git push origin HEAD
    ```

[release blockers]: https://github.com/isovalent/hubble-fgs/labels/release-blocker
[hubble-fgs release]: https://github.com/isovalent/hubble-fgs/releases/new
[hubble-enterprise chart]: https://github.com/isovalent/hubble-enterprise-chart
[hubble-enterprise chart release]: https://github.com/isovalent/hubble-enterprise-chart/releases/new
[umbrella chart]: https://github.com/isovalent/helm-charts
[cilium-enterprise-docs]: https://github.com/isovalent/cilium-enterprise-docs
[cilium-enterprise-dogfooding]: https://github.com/isovalent/cilium-enterprise-dogfooding
[oss-release]: https://github.com/cilium/tetragon/issues/new?assignees=&labels=kind%2Frelease&template=release_template.md&title=vX.Y.Z+release
[tagging]: https://github.com/isovalent/hubble-fgs/blob/master/docs/tagging.md
