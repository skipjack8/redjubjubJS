A minimal RedJubjub implementation for keys and signature.
# Build

## Prerequisites 
1. Install rust

Run the following code in your terminal to download Rustup and install Rust.
```
# curl https://sh.rustup.rs -sSf | sh
```
After installation, run:
```
# source $HOME/.cargo/env
```

2. Install wasm-pack
To build our library, we use `wasm-pack` to pack.

```
$ cargo install wasm-pack
```

3. Install Node with npm. In MacOS, you can run
```
# brew install node
```
In other OS, you can do as Nodejs site.

## Pack

1. Obtain the source code of project.

2. In the root directory of this project, run

```
wasm-pack build --target nodejs --out-dir redjubjub-js
```
If you use this library in browser, run
```
wasm-pack build --target browser --out-dir redjubjub-js
```
`redjubjub-js` will be generated in root directory.

3. In `redjubjub-js` directory, run

```
# npm pack
```
`redjubjub-js-1.0.0.tgz` will be generated in current directory. 

You can install `redjubjub-js-1.0.0.tgz` with npm.

# How to use

## Generate keys

### generate_keys

This method is used for geneating keys and payment address randomly.

```console
> var m = require('redjubjub-js')
> m.generate_keys()
{ sk:
   'c8a6bd72038d62794c551cb4c38b5d586c7df975fb7df819f9adbd571cc5228f',
  ask:
   '58998c6373aa1c2ee724ab16d7a34df2d39bc9c07d68b060b1fffe119167ab00',
  nsk:
   'b3789542ef606d435e654962abc320fa4aad0a424c45b918187ca33052772403',
  ovk:
   '398d3d1889d2f2020ea4c3e76b2ab8711a301a57af1cd09768599d8368cfcaa6',
  ak:
   'd77a6d56ded895d81f7bed8919081124a7e2e28728f4459ba64cf568f54524b7',
  nk:
   '723951fd2d5a29a90d46137d0a5d502fb03524d5ceceefdc97797bbbb8df52eb',
  ivk:
   'd1cc0bf81ead15c55c5cfe4b0b8ec4a735889c11b7d4d281734b42498fa9ce05',
  d: 'c64c97cdcf1e88ab4e5040',
  pk_d:
   'baa02b718197e56f70625452cc9f05c4325b5ba59577d5b8ccf4afc8907a77b2',
  payment_address:
   'ztron1cexf0nw0r6y2knjsgza2q2m3sxt72mmsvf299nylqhzryk6m5k2h04dcen62ljys0fmmyq2x49f' }

```

### generate_keys_by_sk

Generate keys and payment address by `sk`, and `d` is generated randomly.

```console
> m.generate_keys_by_sk('b94113ad57a8808e67edc05e8d3a5bc5aaccf837b83bfa7602a30a14e50c2f95')
{ sk:
   'b94113ad57a8808e67edc05e8d3a5bc5aaccf837b83bfa7602a30a14e50c2f95',
  ask:
   '38c7850745daba75720261b2543cd2d1f316c1f5d4e712c21d4c893d67c38408',
  nsk:
   '399ff8d7d660ca4b8cdf3f2e0ce839f35f6fde80a3d094637699b478405e7507',
  ovk:
   '3a82fe7e4487dd839429874befa09a9f78741ba0de83d08950f776708c9e74e4',
  ak:
   'db0cc9cc4deffd21c4025ae78b55444fa040f244ff7097b35cad4ec96631bb9b',
  nk:
   '532323a356f2ffecf7abd01ad6860f0eea4bf9e7516dd355d0963874e45b7233',
  ivk:
   '48e83b9b5210a8f1a44ad0b5c87203a0a358c34f2511d01e4db743710cebda07',
  d: 'e8f0394a1f6e823901b40a',
  pk_d:
   '017d3fb3a63e03079586dcf24a260bd5c02e18265947ffdf4935bd34a8076a53',
  payment_address:
   'ztron1arcrjjsld6prjqd5pgqh60an5clqxpu4smw0yj3xp02uqtscyev50l7lfy6m6d9gqa49xrmly5e' }

```

### generate_keys_by_sk_d

Generate keys and payment address by `sk`, and `d`.

```console
> m.generate_keys_by_sk_d('b94113ad57a8808e67edc05e8d3a5bc5aaccf837b83bfa7602a30a14e50c2f95','e8f0394a1f6e823901b40a')
{ sk:
   'b94113ad57a8808e67edc05e8d3a5bc5aaccf837b83bfa7602a30a14e50c2f95',
  ask:
   '38c7850745daba75720261b2543cd2d1f316c1f5d4e712c21d4c893d67c38408',
  nsk:
   '399ff8d7d660ca4b8cdf3f2e0ce839f35f6fde80a3d094637699b478405e7507',
  ovk:
   '3a82fe7e4487dd839429874befa09a9f78741ba0de83d08950f776708c9e74e4',
  ak:
   'db0cc9cc4deffd21c4025ae78b55444fa040f244ff7097b35cad4ec96631bb9b',
  nk:
   '532323a356f2ffecf7abd01ad6860f0eea4bf9e7516dd355d0963874e45b7233',
  ivk:
   '48e83b9b5210a8f1a44ad0b5c87203a0a358c34f2511d01e4db743710cebda07',
  d: 'e8f0394a1f6e823901b40a',
  pk_d:
   '017d3fb3a63e03079586dcf24a260bd5c02e18265947ffdf4935bd34a8076a53',
  payment_address:
   'ztron1arcrjjsld6prjqd5pgqh60an5clqxpu4smw0yj3xp02uqtscyev50l7lfy6m6d9gqa49xrmly5e' }

```


## Signature
We also provide methods to sign and verify signature for spend authority signature and binding signature.

### spend authority signature

#### generate_rk_by_ask

Generate public key `rk` by `ask` and  `alpha`.

```JavaScript
function generate_rk_by_ask(ask, alpha)
```

```console
> m.generate_rk_by_ask('e3ebcba1531f6d9158d9c162660c5d7c04dadf77d85d7436a9c98b291ff69a09','2608999c3a97d005a879ecdaa16fd29ae434fb67b177c5e875b0c829e6a1db04')
'10c702d6dff1509502ee5acc0b01d4b4531b2ff53b0dd54488aea6031b5e6d16'
``` 

#### generate_spend_auth_sig

Generate spend authority signature.

```JavaScript
function generate_spend_auth_sig(ask, alpha, message_hash)
```

```console
> m.generate_spend_auth_sig('e3ebcba1531f6d9158d9c162660c5d7c04dadf77d85d7436a9c98b291ff69a09','2608999c3a97d005a879ecdaa16fd29ae434fb67b177c5e875b0c829e6a1db04','3b78fee6e956f915ffe082284c5f18640edca9c57a5f227e5f7d7eb65ad61502')
'40386915d075844a6ea1bd80fd0b6c74bb4556ac0273cb2dd47b7b81eacfb83f3a69ac95cf63b98ad7e3120754cb1033656ce0b0eae9a1f0ace829c14005610a'
```

#### verify_spend_auth_sig

Verify spend authority signature.

```JavaScript
function verify_spend_auth_sig(rk, message_hash, signature)
```

```console
> m.verify_spend_auth_sig('10c702d6dff1509502ee5acc0b01d4b4531b2ff53b0dd54488aea6031b5e6d16', '3b78fee6e956f915ffe082284c5f18640edca9c57a5f227e5f7d7eb65ad61502','40386915d075844a6ea1bd80fd0b6c74bb4556ac0273cb2dd47b7b81eacfb83f3a69ac95cf63b98ad7e3120754cb1033656ce0b0eae9a1f0ace829c14005610a')
true
```

### binding signature

#### generate_pk_by_sk

Generate public key `pk` from private key `sk`.

```JavaScript
function  generate_pk_by_sk(sk)
```

```console
> m.generate_pk_by_sk('e3ebcba1531f6d9158d9c162660c5d7c04dadf77d85d7436a9c98b291ff69a09')
'61a7134af4a6194592735dcda46c3119bdf547bc1e58bd60852cc88ba75f44a3'
```

### generate_binding_sig

Generate binding signature

```JavaScript
function  generate_binding_sig(sk, message_hash)
```

```console
> m.generate_binding_sig('e3ebcba1531f6d9158d9c162660c5d7c04dadf77d85d7436a9c98b291ff69a09','3b78fee6e956f915ffe082284c5f18640edca9c57a5f227e5f7d7eb65ad61502')
'fea301d1f8c0ca3032cdfad36e64aaa27631419fdc84453d994beaa287408adf78e0478b8293eda3b3ba76f5c7efa302116fc577d18f354a5ff42ed25a655001'
```

#### verify_binding_sig

```JavaScript
function  verify_binding_sig(pk, message_hash, signature)
```

```console
> m.verify_binding_sig('61a7134af4a6194592735dcda46c3119bdf547bc1e58bd60852cc88ba75f44a3','3b78fee6e956f915ffe082284c5f18640edca9c57a5f227e5f7d7eb65ad61502','fea301d1f8c0ca3032cdfad36e64aaa27631419fdc84453d994beaa287408adf78e0478b8293eda3b3ba76f5c7efa302116fc577d18f354a5ff42ed25a655001')
true
```

