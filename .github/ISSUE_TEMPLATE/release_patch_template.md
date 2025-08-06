---
name: Release a new patch version of Tetragon Enteprise
about: Create a checklist for an upcoming release
title: 'vX.Y.Z release (patch version)'
labels: kind/release
assignees: ''
---

## Tetragon Enterprise patch release checklist

The following is a release checklist that should be followed when cutting a new patch release of Tetragon Enterprise. Please follow the steps carefully and ask for help in Slack if you have difficulty during the release process.

### Preparation

 - [ ] Set the major and minor version numbers in a `BRANCH` variable:
   ```
   export BRANCH=v1.15
   ```

 - [ ] Check out the latest version of https://github.com/isovalent/hubble-fgs/
    ```
    git fetch origin
    git checkout -B ${BRANCH} origin/${BRANCH}
    make oss-checkout
    ```

 - [ ] Sync latest OSS (if not up-to-date)
    You can run:
    ```
    make oss-sync
    ```

    If the following make target produces a commit in your local tree, create a PR and once merged
    repeat the steps. Otherwise, move to the next step.
    
 - [ ] Check that there are no release blockers
   ```
   gh issue list --label release-blocker/${BRANCH#v}
   ```

 - [ ] Check that there are no Medium, Critical, or High severity CVEs reported in the latest
      [container vulnerability scan](https://github.com/isovalent/hubble-fgs/actions/workflows/container-scan.yaml)
      for the version you are releasing – look at the 'Output scan results' step for the list of
      relevant CVES. If there are any reported issues, either bump the relevant
      dependency (preferred) or work with [#sig-security](https://isovalent.slack.com/archives/CHAA21WJU)
      to triage the issue and add it to the [Tetragon VEX doc](https://github.com/isovalent/hubble-fgs/blob/master/.github/.openvex.json),

- [ ] Check that there are no open PRs (that need to be urgently merged) targeting `$BRANCH`
  ```
  gh pr list --base ${BRANCH} \
    --json title,updatedAt,url,author \
    --template '{{range .}}{{tablerow .url .title .author.login  (timeago .updatedAt)}}{{end}}'
  ```

### Release

- [ ] Set `RELEASE` environment variable to the next patch release:
  ```
  RELEASE=v1.15.1
  ```

  You can use the following command to get a list of the previous patch releases:
  `git tag --list "${BRANCH}*" --sort=version:refname | sed -ne "/$BRANCH\.[0-9]\+$/p"`


- [ ] Open a pull request to update the Helm chart and docs:
  ```
  git checkout -b pr/prepare-$RELEASE $BRANCH

  # update Helm chart
  ./contrib/update-helm-chart.sh $RELEASE
  git add install/kubernetes/

  # update upgrade notes
  bash modules/tetragon-oss/contrib/update-upgrade-notes.sh $RELEASE
  git add contrib/upgrade-notes/

  git commit -s -m "Prepare for $RELEASE release"
  git push origin HEAD
  ```

- [ ] Create the release tags (a "main" tag, and an "api" tag):
  ```
  git checkout $BRANCH && git pull origin $BRANCH
  git tag -a "$RELEASE" -m "$RELEASE release" -s
  git tag -a "api/$RELEASE" -m "api/$RELEASE release" -s
  git push origin "$RELEASE"
  git push origin "api/$RELEASE"
  ```

- When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
  draft release, building artifacts and attaching them to the draft release. Once
  the draft is available in the [releases page]:
  - [ ] Use `tgt-notes` from [tetragon-github-tools](https://github.com/isovalent/tetragon-github-tools/)
        to generate a first version of the release notes based on `release-note/` tags and PR messages.
    
    `./tgt-notes --head=$RELEASE --ee  > $RELEASE.md`

    If you have a recent enough version of `gh` installed, you can use
    `GITHUB_TOKEN=$(gh auth token)` to set the authentication token before
    running the command.

  - [ ] Copy upgrade notes from `contrib/upgrade-notes/vX.Y.Z.md` file into the release notes.
        - Skip if there are no upgrade notes - it's quite likely for patch releases.
        - Review upgrade notes from the corresponding OSS release. Copy them to release notes too if relevant for
          features supported in Tetragon Enterprise.
  - [ ] Review the release notes and update them as needed.
  - [ ] Click on "Publish Release" at the bottom.

### Deploy the new release to tetragon-staging

- [ ] Navigate to the [cilium-enterprise-dogfooding] repo and file a PR to update the Tetragon Enterprise version in tetragon-staging
  - [ ] Edit the `infra/df-tetragon-staging-ce-01/apps/tetragon/kustomization.yaml` file and change the Helm chart version.
  - [ ] If the `infra/df-tetragon-staging-ce-01/apps/tetragon/values.yaml` file overwrites the agent or operator image, remove the overwrite.
  - [ ] Make sure that the `infra/df-tetragon-staging-ce-01/apps/tracing-policies/templates/` directory contains relevant TracingPolicies.
- [ ] Merge the PR and wait for the new release to be deployed.

### Validate the new release in tetragon-staging

- [ ] Check that all Tetragon pods are up and running. Refer to the [cilium-enterprise-dogfooding] README for the access instructions.
- [ ] Check the [Tetragon Health](https://grafana.staging.tetragon.isovalent.com/d/adtue3swqycxsb/tetragon-high-level-health) dashboard in Grafana
  - [ ] error logs
  - [ ] resources usage
  - [ ] any suspicious patterns
- [ ] Check in Grafana if Timescape is ingesting Tetragon events: [Timescape Ingestion](https://grafana.staging.tetragon.isovalent.com/d/XDyOH21Vk/timescape-ingestion). TODO: link a dashboard specific to Tetragon events.
- [ ] Check in Hubble UI if the [Service Map](https://hubble-ui.staging.tetragon.isovalent.com/service-map) is rendered correctly. Uncheck the "Live View" toggle (this enables the Timescape mode) and select a few sample namespaces.
- [ ] Check in Grafana Timescape queries for Tetragon events: [Timescape Queries](https://grafana.staging.tetragon.isovalent.com/d/8v3KZJ14k/timescape-server). TODO: link a dashboard specific to Tetragon events.

Issues found when validating the release in tetragon-staging might not block the release, but should be communicated and documented.

### Update of the OLM manifests and publication of the OLM bundle and catalog index

- [ ] The push of the release tag, triggers the creation of a pull request against the release branch with title "chore: Update CSV image to $RELEASE". Review the PR: the image digests, the `name`, `version` and `replaces` fields are updates with the release specific values. Merge the PR if it looks alright and if it is not for a release candidate. Close it otherwise.
- [ ] Another pull request gets created against the master branch for the addition of the new release to the OLM catalog index. Its title is "chore: Add bundle $RELEASE to the OLM catalog". Review the PR and merge it if it looks alright and if it is not for a release candidate. The merge of the PR triggers the publication of the new version of the OLM catalog index.
- [ ] Validate the publication of the bundle and catalog images under `https://quay.io/repository/isovalent/tetragon-operator-bundle` and `https://quay.io/repository/isovalent/tetragon-operator-index`.

### Documentation

- [ ] Navigate to the [cilium-enterprise-docs] and start working on a PR to document the new release of Tetragon Enterprise.
  Check out a new release branch:
  ```
  git checkout main && git pull origin main
  git checkout -b pr/document-tetragon-$RELEASE
  ```

- [ ] Add realease notes and references to the docs.
  Run:
  ```
  ./scripts/tetragon_add_version.py --tetragon-version $RELEASE
  ```

  The following command, should add the reference files (helm options, agent flags, and metrics) as
  well as a file for release notes (`docs/overview/cilium/releases/release-notes/tetragon/$RELEASE.md`)

- [ ] Edit `docs/overview/cilium/releases/release-notes/tetragon/$RELEASE.md` with the release
  notes. Use the release notes you geneated for the github release as a basis for what goes into
  that file.
  

[release blockers]: https://github.com/isovalent/hubble-fgs/labels/release-blocker
[releases page]: https://github.com/isovalent/hubble-fgs/releases
[cilium-enterprise-docs]: https://github.com/isovalent/cilium-enterprise-docs
[cilium-enterprise-dogfooding]: https://github.com/isovalent/cilium-enterprise-dogfooding
[oss-release]: https://github.com/cilium/tetragon/issues/new?assignees=&labels=kind%2Frelease&template=release_template.md&title=vX.Y.Z+release
