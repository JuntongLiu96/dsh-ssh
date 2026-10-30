# Keyboard-interactive password fallback (Juntong fork)

Version: `1.11.7-juntong.1`, based on upstream tag `v1.11.7`.
Fork: https://github.com/JuntongLiu96/dsh-ssh
Branch: `fix/keyboard-interactive-password`.

## Problem

Some OpenSSH/PAM servers advertise `publickey,keyboard-interactive`, without the SSH `password` method, even though a human enters a password. The original password profile sets only `ConnectConfig.password`, so ssh2 exhausts its configured methods and emits `All configured authentication methods failed`.

## Change

Password profiles now enable ssh2's keyboard-interactive fallback. A connection automatically answers only one hidden (`echo === false`) prompt whose complete label is `Password:` (case-insensitive, allowing spaces/tabs before the colon and after it). Empty informational rounds are accepted. Ordinary password authentication remains available, and private-key/agent profiles do not enable this fallback. Saved credentials and jump hosts use the same resolved authentication path.

Multiple prompts, visible prompts, unrecognized labels, and subsequent nonempty rounds are rejected immediately with `SSH_INTERACTIVE_UNSUPPORTED`. Native password-change requests fail with `SSH_PASSWORD_CHANGE_REQUIRED`. No server-supplied prompt/instruction text or secrets are included in these error messages. Host fingerprint confirmation, abort handling, and transport error listeners are preserved.

This is intentionally **not** a general MFA UI. Use a private key or an interactive SSH client for OTP challenges, password changes, and other interactive flows. A factor misleadingly labeled `Password:` cannot be distinguished from a password by this protocol. The single-response limit applies to keyboard-interactive: ssh2 may already have attempted the ordinary password method before falling back.

The npm package ID remains `@lemoncat7/dsh-ssh` to retain the existing DSH service/client registration and stored credential scopes. The version and repository metadata identify the fork.

## Validation

Run `npm ci --ignore-scripts`, then `npm run build` and `node --test test/connector-keyboard-interactive.test.mjs test/connector.test.mjs`. The dedicated test suite uses local mock servers and dummy credentials; it never connects to real hosts. It covers ordinary authentication, keyboard-only fallback, independent concurrent connections, empty rounds, unsupported/visible/multiple/repeated challenges, wrong passwords, host-key rejection, abort, timeout, callback failures, and listener cleanup.

Local validation results: TypeScript compilation and the production client bundle passed; final authentication/connector/vault/jump/host-key selection passed 29/29 tests. The full upstream-plus-fork suite before the three extra trailing-newline cases passed 206, failed 6, and skipped 2. An unchanged `v1.11.7` worktree reproduced the same six failures: four Windows `fsync` errors, a Unix file-mode assertion, and missing Bash. These pre-existing platform failures are not suppressed or changed by this fork.

Building the client uses esbuild's native executable. Environments prohibiting piped child-process stdio must run the normal build under an approved unrestricted operation rather than bypassing that boundary. Existing subprocess-based tests also require compatible process permissions.
