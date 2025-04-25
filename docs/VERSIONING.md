# Versioning Guidelines

DTVM project follows the [Semantic Versioning (SemVer)](https://semver.org/) specification.

## Version Format

Version numbers are formatted as: **X.Y.Z**, where X, Y, and Z are non-negative integers without leading zeros.

- **X** represents the major version
- **Y** represents the minor version
- **Z** represents the patch version

Additional labels can be used as extensions for pre-releases and version metadata, formatted as: **X.Y.Z-label+metadata**

## Version Increment Rules

1. **Major version (X)**: Increment when making incompatible API changes
2. **Minor version (Y)**: Increment when adding functionality in a backward-compatible manner
3. **Patch version (Z)**: Increment when making backward-compatible bug fixes

## Pre-release Versions

Pre-release versions can be indicated by adding a hyphen and an identifier after the version number, for example:

- **1.0.0-alpha.1**
- **1.0.0-beta.2**
- **1.0.0-rc.1**

Pre-release versions have lower precedence than the associated normal version.

## Release Process

1. Each significant version should be developed and tested on a `dev` or feature branch before release
2. Prior to version release, update the `CHANGELOG.md` file to record all changes for that version
3. Tag versions with Git tags in the format `v1.0.0`
4. Release versions through GitHub Releases, including the corresponding CHANGELOG

## CHANGELOG Requirements

The CHANGELOG should list versions from newest to oldest, with each version including the following sections:

- **Added**: New features
- **Changed**: Changes to existing functionality
- **Deprecated**: Features that are still supported but will be removed in upcoming releases
- **Removed**: Features that have been removed
- **Fixed**: Bug fixes
- **Security**: Security-related fixes

## Version Examples

### Major Version Upgrade (Incompatible Changes)
```
1.0.0 -> 2.0.0
```

### Minor Version Upgrade (Backward-compatible New Features)
```
1.0.0 -> 1.1.0
```

### Patch Version Upgrade (Backward-compatible Bug Fixes)
```
1.1.0 -> 1.1.1
```

## Tagging Release Versions

Use Git tags to mark each release version:

```bash
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
``` 