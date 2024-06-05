---
name: Release a new patch version of Tetragon Enteprise (versions <= v1.11)
about: Create a checklist for an upcoming release
title: 'v1.11.Z release'
labels: kind/release
assignees: ''
---

## Tetragon Enterprise release checklist

The following is a release checklist that should be followed when cutting a new release of Tetragon Enterprise. Please follow the steps carefully and ask for help in Slack if you have difficulty during the release process.

### Cutting the Tetragon Enterprise release

- [ ] Check that there are no [release blockers].
- [ ] Check that there are no Critical or High severity CVEs reported in the latest
      [container vulnerability scan](https://github.com/isovalent/hubble-fgs/actions/workflows/container-scan-twistcli.yaml)
      for the version you are releasing (X.Y) – look at the 'Output scan results' step for the list of
      relevant CVES. If there are any reported issues, either bump the relevant
      dependency (preferred) or work with [#sig-security](https://isovalent.slack.com/archives/CHAA21WJU)
      to triage the issue and add it to the [Tetragon VEX doc](https://github.com/isovalent/hubble-fgs/blob/master/.github/vex-data.vex.json),
      which will exclude it from the scan results if it is a false positive.
- [ ] Set `RELEASE` environment variable. For example, if you are releasing `v1.11.4`:
  ```
  export RELEASE=v1.11.4
  ```
- [ ] Set the `BRANCH` environment variable to the major/minor version branch. For example, if you are releasing `v1.11.4`:
  ```
  export BRANCH=v1.11
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
- [ ] Only for major/minor release, update `.github/renovate.json5` to include the new stable branch and remove the unsupported branch.
- [ ] Generate [release notes][hubble-fgs release] for the new release
  - [ ] Find the "main" release tag you generated
  - [ ] Click "generate release notes"
  - [ ] Click "publish release"


### Updating the hubble-enterprise helm chart

- [ ] Navigate to the [hubble-enterprise chart] repo and file a PR to update the Helm chart version

  - [ ] Check out a new release branch on the v1.11 branch
  ```
  git fetch origin
  git checkout -b pr/prepare-fgs-$RELEASE origin/v1.11
  ```
  - [ ] Update `values.yaml` and change the `hubble-enterprise` and `hubble-enterprise-operator` image `tag` values to the new "main" release tag. Example diff:
  ```diff
   diff --git a/values.yaml b/values.yaml
   index 6a172ac..c5f10a1 100644
   --- a/values.yaml
   +++ b/values.yaml
   @@ -62,7 +62,7 @@ enterprise:
      image:
        override: ~
        repository: quay.io/isovalent/hubble-enterprise
   -    tag: v1.11.3
   +    tag: v1.11.4
      metadataImage:
        override: ~
        repository: quay.io/isovalent/hubble-enterprise-metadata
   @@ -206,7 +206,7 @@ hubbleEnterpriseOperator:
      image:
        override: ~
        repository: quay.io/isovalent/hubble-enterprise-operator
   -    tag: v1.11.3
   +    tag: v1.11.4
        # hubble-enterprise-operator image-digest
        suffix: ""
   
  ```
  - [ ] Run `test.sh` to generate new documentation and verify that there are no issues in the Helm templating. Ensure that the script executes without any failures:
  ```
  ./test.sh
  ```
  - [ ] Add and commit the results and file a pull request on [GitHub][hubble-enterprise chart] (HINT: you can just click the link in the output of the `git push` command):
  ```
  git commit -a -m "Prepare for $RELEASE FGS release" -s && git push origin HEAD
  ```
  - [ ] After your PR is merged, tag a [new release][hubble-enterprise chart release] of `hubble-enterprise-chart`.
    - [ ] Click "generate release notes" and create a new tag with the appropriate version bump
    - [ ] NOTE: The hubble-enterprise-chart version is not strictly in lockstep with the FGS version, so don't worry if they don't match
    - [ ] Click "publish release"


**IF YOU ARE DOING A RELEASE CANDIDATE, STOP HERE.**

### Documentation

- [ ] Navigate to the [cilium-enterprise-docs] and start working on a PR to document the new release of Tetragon Enterprise.
  Check out a new release branch:
  ```
  git checkout main && git pull origin main
  git checkout -b pr/document-tetragon-$RELEASE
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
