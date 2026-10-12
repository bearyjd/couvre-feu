# Operator SSH agent

Router maintenance uses the operator’s encrypted admin key through an existing SSH agent. This is separate from the policy service’s constrained router identity. Keep private keys and passphrases outside the repository and evidence files.

Before an unattended session, confirm that your terminal and the automation process use the same agent socket:

```sh
printf '%s\n' "$SSH_AUTH_SOCK"
ssh-add -t 12h ~/.ssh/couvre-feu-admin
ssh-add -l
```

Enter the passphrase in your local terminal. Compare the listed fingerprint with the previously verified admin identity. Use the socket path recorded in the reviewed procedure; creating a different agent does not update that procedure.

`-t 12h` requests a maximum key lifetime, starting when it is loaded. An agent restart can remove the key earlier. See the [OpenSSH ssh-add manual](https://man.openbsd.org/ssh-add).

If the agent has no identities or cannot be contacted, restore the existing socket/key setup and verify fingerprints before live work resumes. Retain strict host-key checking, public-key-only batch authentication and disabled agent forwarding. Do not remove the key’s passphrase or add password fallbacks to continue automation.

Key availability does not extend router authorization. Stop new router operations when the approved window ends. An uncertain mutating outcome requires its existing evidence and recovery rules; reloading the key does not authorize replay or rollback.
