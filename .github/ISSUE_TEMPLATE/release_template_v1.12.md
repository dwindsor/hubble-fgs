---
name: Release a new version of Tetragon Enteprise (version v1.12)
about: Create a checklist for an upcoming release
title: 'v1.12.Z release'
labels: kind/release
assignees: ''
---

## Tetragon Enterprise release checklist

### Cutting the Tetragon Enterprise release

- [ ] Check that there are no [release blockers].
- [ ] Check that there are no Critical or High severity CVEs reported in the latest
      [container vulnerability scan](https://github.com/isovalent/hubble-fgs/actions/workflows/container-scan-twistcli.yaml)
      for the version you are releasing (1.12) – look at the 'Output scan results' step for the list of
      relevant CVES. If there are any reported issues, either bump the relevant
      dependency (preferred) or work with [#sig-security](https://isovalent.slack.com/archives/CHAA21WJU)
      to triage the issue and add it to the [Tetragon VEX doc](https://github.com/isovalent/hubble-fgs/blob/master/.github/vex-data.vex.json),
      which will exclude it from the scan results if it is a false positive.
- [ ] Set `RELEASE` environment variable. For example, if you are releasing `v1.12.6`:
  ```
  export RELEASE=v1.12.6
  ```
- [ ] Open a pull request to update the Helm chart and docs:
  ```
  git checkout -b pr/prepare-$RELEASE

  # update Helm chart
  ./contrib/update-helm-chart.sh $RELEASE
  git add install/kubernetes/

  # update upgrade notes
  bash modules/tetragon-oss/contrib/update-upgrade-notes.sh $RELEASE
  git add contrib/upgrade-notes/

  git commit -s -m "Prepare for $RELEASE release"
  git push origin HEAD
  ```
- [ ] Set the `BRANCH` environment variable to the major/minor version branch. For example, if you are releasing `v1.12.7`:
  ```
  export BRANCH=v1.12
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
- When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
  draft release, building artifacts and attaching them to the draft release. Once
  the draft is available in the [releases page]:
  - [ ] Use `tgt-notes` from [tetragon-github-tools](https://github.com/isovalent/tetragon-github-tools/)
        to generate a first version of the release notes based on `release-note/` tags and PR messages.
  - [ ] Copy upgrade notes from `contrib/upgrade-notes/vX.Y.Z.md` file into the release notes.
        - Skip if there are no upgrade notes - it's quite likely for patch releases.
        - Review upgrade notes from the corresponding OSS release. Copy them to release notes too if relevant for
          features supported in Tetragon Enterprise.
  - [ ] Review the release notes and update them as needed.
  - [ ] Make sure the "Set as a pre-release" and "Set as the latest release" checkboxes are set correctly.
        Every `-pre.N` or `-rc.N` release should be marked as a pre-release, and a stable release with the highest
        version should be marked as latest.
  - [ ] Click on "Publish Release" at the bottom.

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
  git checkout main && git pull origin main
  git checkout -b pr/document-tetragon-$RELEASE
  ```
- Add release notes to the docs
  - [ ] Edit `docs/operations-guide/releases/release-notes/tetragon/index.rst` to add a new entry for the new version of Tetragon Enterprise. Example diff:
    ```diff
    diff --git a/docs/operations-guide/releases/release-notes/tetragon/index.rst b/docs/operations-guide/releases/release-notes/tetragon/index.rst
    index 98284b7..92a1d34 100644
    --- a/docs/operations-guide/releases/release-notes/tetragon/index.rst
    +++ b/docs/operations-guide/releases/release-notes/tetragon/index.rst
    @@ -4,6 +4,7 @@ Release Notes - Tetragon Enterprise
     .. toctree::
       :maxdepth: 1

    +  v1.12.6
       v1.12.5
       v1.12.4
       v1.12.3
    ```
   - [ ] Create a new file `docs/operations-guide/releases/release-notes/tetragon/$RELEASE.md`. Use the release notes you generated for the GitHub release as a basis for what goes into the file. You can use the following as a template:
     ```markdown
     # vX.Y.Z

     ## Upgrade notes
     * Upgrade notes here

     ## Features
     * Major changes here

     ## Enhancements
     * Minor changes here
     ```
- [ ] Install [gh cli](https://github.com/cli/cli) locally and run the script
`scripts/tetragon-update-doc-references.sh` to update helm charts, daemon flags and other references.
- [ ] If there are any new features introduced, list them under the "Cilium Enterprise Feature Maturity List"
  - [ ] See `docs/operations-guide/features/status.rst`
- [ ] Ping feature owners to add documentation for undocumented new features

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
    -    tag: v1.12.5
    +    tag: v1.12.6
       metadataImage:
         override: ~
         repository: quay.io/isovalent/hubble-enterprise-metadata
    @@ -182,7 +182,7 @@ hubbleEnterpriseOperator:
       image:
         override: ~
         repository: quay.io/isovalent/hubble-enterprise-operator
    -    tag: v1.12.5
    +    tag: v1.12.6
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

  - [ ] Navigate to the [cilium-enterprise-docs] and start working on a PR to document the new release of Hubble Enterprise.
    Check out a new release branch:
    ```
    git checkout main && git pull origin main
    git checkout -b pr/document-hubble-enterprise-$RELEASE
    ```
  - Add release notes to the docs
    - [ ] NOTE: The hubble-enterprise-chart version is not strictly in lockstep with the Tetragon Enterprise version. In practice, the versions will not match.
    - [ ] Edit `docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst` to add a new entry for the new version of Hubble Enterprise. Example diff:
      ```diff
      diff --git a/docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst b/docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst
      index 98284b7..92a1d34 100644
      --- a/docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst
      +++ b/docs/operations-guide/releases/release-notes/hubble-enterprise/index.rst
      @@ -4,6 +4,7 @@ Release Notes - Hubble Enterprise
       .. toctree::
         :maxdepth: 1

      +  v1.12.7
         v1.12.6
         v1.12.5
         v1.12.4
      ```
     - [ ] Create a new file `docs/operations-guide/releases/release-notes/hubble-enterprise/$RELEASE.md`. The `$RELEASE` is the chart version, and the version linked is the Tetragon version released.t
       ```markdown
        # v1.12.7 (2024-07-11)

        ## What's Changed

        * Update [Tetragon to v1.12.6](../tetragon/v1.12.6.md)
       ```

[release blockers]: https://github.com/isovalent/hubble-fgs/labels/release-blocker
[releases page]: https://github.com/isovalent/hubble-fgs/releases
[hubble-enterprise chart]: https://github.com/isovalent/hubble-enterprise-chart
[hubble-enterprise chart release]: https://github.com/isovalent/hubble-enterprise-chart/releases/new
[cilium-enterprise-docs]: https://github.com/isovalent/cilium-enterprise-docs
[cilium-enterprise-dogfooding]: https://github.com/isovalent/cilium-enterprise-dogfooding
[oss-release]: https://github.com/cilium/tetragon/issues/new?assignees=&labels=kind%2Frelease&template=release_template.md&title=vX.Y.Z+release
[tagging]: https://github.com/isovalent/hubble-fgs/blob/master/docs/tagging.md
