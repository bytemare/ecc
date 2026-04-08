# Releasing

This project publishes the `github.com/bytemare/secp256k1` Go module following Semantic Versioning. Releases are coordinated through Git tags and GitHub Actions workflows defined in this repository.

## Release Checklist

1. **Plan the version**
   - Determine the next SemVer tag (`vMAJOR.MINOR.PATCH`).
   - Open or update an issue/PR describing notable changes and migration impact (if any).

2. **Update documentation**
   - Add release notes to [CHANGELOG.md](../CHANGELOG.md) under a new version heading.
   - Move entries from `[Unreleased]` to the new version section.
   - Verify README examples and policy docs (`docs/security_model.md`, `docs/architecture_and_guidelines.md`) still apply.

3. **Run validation locally**

   Run the validation suite as described in [CONTRIBUTING.md §5](../.github/CONTRIBUTING.md#5-quality-checks).

4. **Tag and publish a new release**

   ```bash
   make -C .github release tag=vX.Y.Z
   ```

   The `.github/Makefile` release target creates a signed annotated tag and pushes it.

5. **Let automation publish artifacts**
   - Pushing the tag triggers `.github/workflows/wf-release.yaml`.
   - The release workflow delegates to a pinned reusable `bytemare/slsa` workflow.
   - The exact artifact/attestation set is defined by that pinned reusable workflow version. Review the workflow run logs and the GitHub release assets to confirm they match current project policy.
   - If needed, run `.github/workflows/wf-verify.yaml` manually to verify a tagged release using the pinned reusable verification workflow.

6. **Publish notes**
   - If the automated release does not include human-readable notes, edit the GitHub release and paste the corresponding `CHANGELOG.md` entry.

7. **Post-release follow-up**
   - Announce the release in the relevant issue/discussion.
   - Triage downstream reports quickly and start planning the next iteration.

## Emergency Releases

For high-severity security issues, coordinate privately via the process in [SECURITY.md](../.github/SECURITY.md). Patch releases should include only the minimal changes required to resolve the issue.
