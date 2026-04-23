# Versioning Policy

- Specification artifacts use semantic versioning with explicit draft, RC, and
  GA milestones.
- Reference implementation artifacts track the same major/minor contract as the
  public spec, with patch releases reserved for compatible fixes.
- Golden vectors are versioned and cannot change without a version bump and
  changelog entry.
- Any breaking change to canonicalization, crypto suites, auth semantics, or
  storage-encryption requirements requires a major or explicitly marked RC
  transition.

