# Releasing

Releases are annotated, signed git tags named `vMAJOR.MINOR.PATCH` that follow semantic versioning. The version in the workspace `Cargo.toml`, `CITATION.cff`, and the tag must agree.

## One-time setup: SSH signing key

```bash
# 1. use an existing key or create a dedicated signing key
ssh-keygen -t ed25519 -C "git-signing" -f ~/.ssh/git_signing

# 2. tell git to sign with it
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/git_signing.pub
git config --global tag.gpgSign true
git config --global commit.gpgSign true      # optional: sign every commit

# 3. register the PUBLIC key on GitHub as a *Signing Key*
#    GitHub → Settings → SSH and GPG keys → New SSH key → Key type: Signing Key
cat ~/.ssh/git_signing.pub
```

For local verification, create an allowed-signers file:

```bash
echo "<your-email> $(cat ~/.ssh/git_signing.pub)" > ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

(GPG works equally well; use `gpg.format openpgp` and upload the armored public key to GitHub.)

## Cutting a release

1. Make sure CI is green on `main`.
2. Update the version in `Cargo.toml` (`[workspace.package]`), `CITATION.cff` (`version`, `date-released`), and add a section to `CHANGES.md`.
3. Commit, then tag and push:

```bash
git tag -s v0.1.0 -m "v0.1.0"
git verify-tag v0.1.0
git push origin main v0.1.0
```

GitHub shows a "Verified" badge on the tag when the signing key is registered.

## Verifying a release

```bash
git fetch --tags
git verify-tag v0.1.0
```
