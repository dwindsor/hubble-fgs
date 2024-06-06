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
- [ ] Make sure you add the `-rc.N` suffix to the version number for release candidates (rc)

Branch `X.Y` may not exist, because we have not branched out yet. This can only happen for
`X.Y.0-rc.N` or `X.Y.0` releases. In this case:

   * If release is `X.Y.0`:
       * Create `X.Y` branch
       * Copy the file `install/olm/bundle/manifests/tetragon-operator.clusterserviceversion.yaml` from the previous release branch, e.g. from `1.3` if creating release `1.4.0`.
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
- [ ] Check that there are no Critical or High severity CVEs reported in the latest
      [container vulnerability scan](https://github.com/isovalent/hubble-fgs/actions/workflows/container-scan-twistcli.yaml)
      for the version you are releasing (X.Y) – look at the 'Output scan results' step for the list of
      relevant CVES. If there are any reported issues, either bump the relevant
      dependency (preferred) or work with [#sig-security](https://isovalent.slack.com/archives/CHAA21WJU)
      to triage the issue and add it to the [Tetragon VEX doc](https://github.com/isovalent/hubble-fgs/blob/master/.github/vex-data.vex.json),
      which will exclude it from the scan results if it is a false positive.
- [ ] Set `RELEASE` environment variable. For example, if you are releasing `v1.9.0`:
  ```
  export RELEASE=v1.9.0
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

### Update of the OLM manifests and publication of the OLM bundle and catalog index

- [ ] The push of the release tag, triggers the creation of a pull request against the release branch with title "chore: Update CSV image to $RELEASE". Review the PR: the image digests, the `name`, `version` and `replaces` fields are updates with the release specific values. Merge the PR if it looks alright and if it is not for a release candidate. Close it otherwise.
- [ ] Another pull request gets created against the master branch for the addition of the new release to the OLM catalog index. Its title is "chore: Add bundle $RELEASE to the OLM catalog". Review the PR and merge it if it looks alright and if it is not for a release candidate. The merge of the PR triggers the publication of the new version of the OLM catalog index.
- [ ] Validate the publication of the bundle and catalog images under `https://quay.io/repository/isovalent/tetragon-operator-bundle` and `https://quay.io/repository/isovalent/tetragon-operator-index`.

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

    +  v1.9.3
       v1.9.2
       v1.9.1
       v1.9.0
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

[release blockers]: https://github.com/isovalent/hubble-fgs/labels/release-blocker
[releases page]: https://github.com/isovalent/hubble-fgs/releases
[hubble-enterprise chart]: https://github.com/isovalent/hubble-enterprise-chart
[hubble-enterprise chart release]: https://github.com/isovalent/hubble-enterprise-chart/releases/new
[umbrella chart]: https://github.com/isovalent/helm-charts
[cilium-enterprise-docs]: https://github.com/isovalent/cilium-enterprise-docs
[cilium-enterprise-dogfooding]: https://github.com/isovalent/cilium-enterprise-dogfooding
[oss-release]: https://github.com/cilium/tetragon/issues/new?assignees=&labels=kind%2Frelease&template=release_template.md&title=vX.Y.Z+release
[tagging]: https://github.com/isovalent/hubble-fgs/blob/master/docs/tagging.md
