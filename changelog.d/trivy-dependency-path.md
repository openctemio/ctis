### Added: trivy findings say whether the package is direct and how it comes in

- With the package list of a language result (`trivy --list-all-pkgs`), each vulnerability gets `vulnerability.is_direct`, `vulnerability.dependency_path` (the shortest chain of package ids from the project or the direct dependency to the vulnerable package, at most 32 entries), the package's PURL when the record has none, and the lockfile with the package's first line as its location.
- Dependencies of a language result carry the lockfile as `path` and their lockfile lines as `locations`; `Indirect` sets the relationship when trivy gives no `Relationship`.
- OS-package results are unchanged: their target names an image, not a file.
