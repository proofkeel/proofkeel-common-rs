# Versioned Git hooks

Enable these hooks once per clone:

```sh
git config core.hooksPath .githooks
```

`commit-msg` rejects commits without a valid DCO `Signed-off-by` trailer.
Create one with `git commit --signoff`, or amend the current commit with
`git commit --amend --signoff`.

The GitHub DCO workflow is the authoritative shared gate; the local hook
provides the same failure before a commit leaves the workstation.
