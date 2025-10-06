# Releasing

This project publishes Go modules following Semantic Versioning. Releases are manual and should be coordinated via GitHub pull requests.

## Prerequisites

- Ensure you have push access to `github.com/bytemare/ecc`.
- Install the required Go toolchain versions (see CI matrix for currently supported versions).
- Sign commits and tags with your DCO-compliant identity.

## Release Checklist

1. **Plan the version**
   - Determine the next SemVer tag (`vMAJOR.MINOR.PATCH`).
   - Open or update an issue/PR describing notable changes.

2. **Update documentation**
   - Add release notes to [CHANGELOG.md](../CHANGELOG.md) under a new version heading.
   - Verify README snippets and policy docs still apply.

3. **Run validation locally**
   ```bash
   go test ./...
   go vet ./...
   # Optional: golangci-lint run
   ```

4. **Tag the release**
   ```bash
   git commit -am "chore: cut vX.Y.Z"
   git tag -s vX.Y.Z
   ```
   - If signing keys are unavailable, create a lightweight tag (`git tag vX.Y.Z`).

5. **Push to GitHub**
   ```bash
    git push origin main
    git push origin vX.Y.Z
   ```

6. **Create the GitHub Release**
   - Draft a new release from `vX.Y.Z`.
   - Include the changelog entry and any upgrade notes.
   - Upload artifacts (e.g., SBOM) if applicable.

7. **Post-release follow-up**
   - Announce the release in the relevant issue or discussion.
   - Triage any downstream reports and start planning the next iteration.

## Emergency Releases

For high-severity security issues, coordinate privately via the process in [.github/SECURITY.md](../.github/SECURITY.md). Patch branches should include only the minimal changes required to resolve the issue.
