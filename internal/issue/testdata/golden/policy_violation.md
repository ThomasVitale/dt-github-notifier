# [DT] Policy Violation: policyName in projectName projectVersion

Labels: security, policy-violation, dependency-track, violation-state:fail

## :rotating_light: Policy Violation Detected

| Field | Value |
|---|---|
| **Project** | `projectName projectVersion` |
| **Component** | `componentName componentVersion` |
| **Policy** | `policyName` |
| **Violation State** | `FAIL` |
| **Type** | `OPERATIONAL` |
| **Condition** | `PACKAGE_URL` `IS` `pkg:maven/foo/bar@1.2.3` |
| **Timestamp** | `2006-06-06T06:06:06.666Z` |

**Message:**
```
Package URL pkg:maven/foo/bar@1.2.3 is not allowed
```

> This issue was created automatically by dt-github-notifier (deduplication key: `dtgn-58f5f1cbe91bd0d7f5cfc14e761cf13b`).
