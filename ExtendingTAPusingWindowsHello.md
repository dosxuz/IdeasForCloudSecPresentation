# Lateral Movement and on-prem NT Hash dumping with Microsoft Entra TAPs (Temporary Access Passes)

- Used to configure temp password for user accounts
  - Satisfy MFA controls
  - Sets up Passwordless authentications like `FIDO` and `Windows Hello For Business`

## Configuring TAP

- It can be configured by admin
- It can also be done using Graph API
  - `UserAuthenticationMethod.ReadWrite.All` delegated permissions is required for this
  - No in-built MS app has this permissions

- Go to Users -> Hybrid -> Authentication Methods -> Select Add Authentication Methods -> Temporary Access Pass Details

- Act as alternative credentials for the user
- Can be used while legitimate user is not interrupted
  - Useful for password resets, since it invalidates user's current sessions
- TAP also counts as MFA, there won't be any generation of text messages.

## Abusing TAP for Lateral movement

- TAP is valid during the configured lifetime only
- We can change the validity of the TAP
- Longer validity might be suspicious, so we can make it short, to minimize the legitimate user being prompted

### Configuring Windows Hello For Business Keys with a TAP

- We need special tokens for this.
- Similar to how Windows upgradres PRT to include MFA claim after obtaining them with only a password
- We don't use the authentication method directly in the PRT request
  - We use a special refresh token that acts as an intermediary

- Windows Hello provisioning also requires us to have device in the tenant
  - Registering or joining devices is enabled in almost all tenants
- We can also abuse an existing device
  - This would be complicated if TPM is involved

- First we need to authenticate using TAP using the `prtenrich` command
- This also works without existing PRT using the flag `--no-prt` which allows us to use TAP for authetnication

```
roadtx prtenrich -u hybrid@hybrid.iminyour.cloud --no-prt
```

- This will prompt us for the TAP and give us refresh token
- If we do not have a device certificate/key, we can also use this refresh token to register a device

```
roadtx gettokens --refresh-token <token> -c broker -r drs
```

- We can join / register a device using the device module

```
roadtx device -n blogtest2 -a register
```

- Using the newly registered device we can get a PRT

```
roadtx prt -r <refreshtoken> -c blogtest2.pem -k blogtest2.key
```

- PRT will be valid for as long as the TAP itself.
- It will get refused after the TAP expiry

- For actual persistence, we need to provision additional credentials to this account
- In this case it will be Windows Hello for Business
  - Can be used after the TAP expires
- Use `prtenrich` to get an access token for Windows Hello provisioning, then register the actual hello key

```
roadtx prtenrich --ngcmfa-drs-auth
roadtx winhello -k hybriduser.key
```

- `prtenrich` command will automatically proceed if we did the TAP authentication within last 10 mins
  - If not, we can just use TAP again to comply with MFA requirements (given TAP has multiple uses)
- `winhello` command provisions the key for our user
  - If we want, we can use it toget new PRT, that is valid for longer and also counts as MFA

```
roadtx prt -hk hybriduser.key -c blogtest2.pem -k blogtest2.key -u hybrid@hybrid.iminyour.cloud
```

- This PRT can be used with `prtauth` adn `browserprtauth` to either get tokens or to browse the web as the victim

### Obtaining NT hashes of victim via TAP

- The PRT came with a Kerberos TGT for the on-prem AD that our victim is part of
- This is due to the `Cloud Kerberos Trust` feature
- While a TAP by definition is temporary, the TGT that we received is valid for 10 hours
  - This exceeds the validity of the TAP itself
- Since Cloud Kerberos trust enables recovering legacy credentials (NT Hashes)
  - We can obtain the NT hash of our victim (provided that we have line-of-sight to an on-prem AD DC)
  - NT hash can be used to request TGTs even after TAP expires or our access in the cloud was revoked
  - If the original password of the user is weak, we can recover the plain text password by brute forcing the NT hash with tools such as hashcat

Therefore, we have the following:

1. TAPs enabled in the tenant
2. Suffiecient access to provision TAPs on our victims
3. Cloud Kerberos trust enabled
4. Line of sight to on-prem AD

- We can obtain the NT hash for anyone we can provision a TAP for, without requiring to configure persistence on their account
- This all can be done with a single device identity to leave as few traces as possible
- This can be used as somewhat noisy hash dump method entirely from Entra

#### Limitations

We cannot target the following accounts

1. Users like Domain Admins (which aren't synced to Entra) are not affected
2.

Finally we will re-use PRT we got in first step, i.e. the one requested using the TAP, before we enrolled a Windows Hello key.

This PRT will contains partial TGT, which we can exchange for a full TGT using `partialtofulltgt.py` script

```
python partialtofulltgt.py -f roadtx.prt hybrid.iminyour.cloud/hybrid
```

- To do this for more users, provision a TAP fro them too
  - Request a TGT with the TAP and then recover the NT hash
  - Write a script that loops through this and recovers as many hashes as possible without making permanent changes to the accounts or causing impact to the real user of the account
