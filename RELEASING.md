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
git tag -s v0.2.0 -m "v0.2.0"
git verify-tag v0.2.0
git push origin main v0.2.0
```

GitHub shows a "Verified" badge on the tag when the signing key is registered.

## Verifying a release

```bash
git fetch --tags
git verify-tag v0.2.0
```

## Dry run

Before tagging, run the workflow by hand (Actions, release, Run workflow). It does everything a tag does except publish: both archives are built, checked (checksum, the program starts, the dashboard and start script are inside) and kept as artifacts for a week, and the container images are built but not pushed.

## What pushing a tag does

`.github/workflows/release.yml` runs on every tag matching `vMAJOR.MINOR.PATCH`:

1. checks that the tag equals the version in `Cargo.toml`;
2. builds the Linux x86_64 binary with the dashboard assets and publishes `tlsfp-<version>-linux-x86_64.tar.gz`, its SHA-256 file and a build provenance attestation as a GitHub release;
3. publishes the container images `ghcr.io/<owner>/tlsfp` (sensor and API) and `ghcr.io/<owner>/tlsfp-dashboard` (nginx and the dashboard) with the version and `latest` tags.

Verify a downloaded archive with `sha256sum -c tlsfp-*.sha256` and `gh attestation verify tlsfp-*.tar.gz --repo <owner>/<repo>`. The first run of this workflow is the first test of it; if a step fails, fix the workflow, delete the tag and release, and push the tag again.

## Manual check before announcing a release: live capture on Windows

CI cannot install Npcap unattended, so this one is done by hand on a Windows machine with Npcap installed, using the release zip:

1. `.\start-windows.ps1` opens the dashboard and the header says `LIVE`, not `REPLAY`.
2. Browse to a few sites. Handshakes appear on Scope within a second or two; Traffic shows conversations with your own address as the local side.
3. `tlsfp.exe interfaces` lists your adapters with descriptions; `.\start-windows.ps1 -Interface "Wi-Fi"` (or your adapter's name) captures on it.
4. With Npcap uninstalled, `tlsfp.exe serve --live auto` prints the "needs Npcap" message and exits; `tlsfp.exe pcap FILE` still works.
5. Record the Windows version, Npcap version and result in the release notes.

Already observed: live capture worked on one Windows machine on 2026-10-24 (see `docs/LIVE_CAPTURE.md`); steps 3 and 4 and the versions are still to be recorded for this release.
