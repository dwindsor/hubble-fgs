---
name: Create a new pre-release of Tetragon Enteprise
about: Create a checklist for an upcoming release
title: 'vX.Y.Z-pre.A release'
labels: kind/release
assignees: ''
---

## Tetragon Enterprise release checklist

The following is a release checklist that should be followed when cutting a new release of Tetragon Enterprise. Please follow the steps carefully and ask for help in Slack if you have difficulty during the release process.

### Cutting the Tetragon Enterprise release

- [ ] Check that there are no [release blockers](https://github.com/isovalent/hubble-fgs/labels/release-blocker).
- [ ] Check that there are no Medium, Critical, or High severity CVEs reported in the latest
      [container vulnerability scan](https://github.com/isovalent/hubble-fgs/actions/workflows/container-scan.yaml)
      for the version you are releasing (X.Y) – look at the 'Output scan results' step for the list of
      relevant CVES. If there are any reported issues, either bump the relevant
      dependency (preferred) or work with [#sig-security](https://isovalent.slack.com/archives/CHAA21WJU)
      to triage the issue and add it to the [Tetragon VEX doc](https://github.com/isovalent/hubble-fgs/blob/master/.github/.openvex.json),
      which will exclude it from the scan results if it is a false positive.
- [ ] Set `RELEASE` environment variable to the next -rc. For example, if you are releasing `v1.18.0`:
  ```
  export RELEASE=v1.18.0-rc.X
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
- [ ] Set the `BRANCH` environment variable to the major/minor version branch. For example, if you are releasing `v1.18.0`:
  ```
  export BRANCH=v1.18
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
