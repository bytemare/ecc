# Releasing

This project publishes Go modules following Semantic Versioning. Releases are coordinated via GitHub pull requests and automated workflows.

## Release Checklist

1. **Plan the version**
   - Determine the next SemVer tag (`vMAJOR.MINOR.PATCH`).
   - Open or update an issue/PR describing notable changes.

2. **Update documentation**
   - Add release notes to [CHANGELOG.md](../CHANGELOG.md) under a new version heading.
   - Move entries from `[Unreleased]` to the new version section.
   - Verify README snippets and policy docs still apply.

3. **Run validation locally**
   - Run the validation suite as described in [CONTRIBUTING.md §5](../.github/CONTRIBUTING.md#5-quality-checks).

4. **Tag the release**
   ```bash
   git commit -am "chore: cut X.Y.Z"
   git tag -s vX.Y.Z
   ```
   - If signing keys are unavailable, create a lightweight tag (`git tag vX.Y.Z`).

5. **Push to GitHub**
   ```bash
    git push origin main
    git push origin vX.Y.Z
   ```

6. **Let automation publish artifacts**
   - Pushing the tag triggers `.github/workflows/wf-release.yaml`.
   - The workflow builds a source archive, generates a CycloneDX SBOM, records checksums, and uploads an SBOM attestation.
   - A reusable SLSA provenance job attaches the provenance bundle to the release.
   - Monitor the workflow run for success. Confirm that the release contains the tarball, SBOM, and provenance `.intoto.jsonl` assets.

7. **Publish notes**
   - If the automated release does not include human-readable notes, edit the GitHub release, paste the `CHANGELOG.md` entry, and save.

8. **Post-release follow-up**
   - Announce the release in the relevant issue or discussion.
   - Triage any downstream reports and start planning the next iteration.

## Emergency Releases

For high-severity security issues, coordinate privately via the process in [.github/SECURITY.md](../.github/SECURITY.md). Patch branches should include only the minimal changes required to resolve the issue.
