const {
    generate_rk_from_ask,
    generate_spend_auth_sig,
    verify_spend_auth_sig,
    generate_pk_from_sk,
    generate_binding_sig,
    verify_binding_sig,
    generate_keys,
    generate_keys_by_sk,
    generate_keys_by_sk_d
} = require("./redjubjub-js")


var msg = "3b78fee6e956f915ffe082284c5f18640edca9c57a5f227e5f7d7eb65ad61502"
var sk = "e3ebcba1531f6d9158d9c162660c5d7c04dadf77d85d7436a9c98b291ff69a09"
//binding sigature
const pk = generate_pk_from_sk(sk);
console.log("pk " + pk)

const sig = generate_binding_sig(sk, msg)
console.log("binding signature is " + sig)

var verify_binding_sig_res = verify_binding_sig(pk, msg, sig)
console.log("Verify binding signature " + verify_binding_sig_res)

//spend authority signature
console.log("__________________spend authority signature________________________")
var alpha = "2608999c3a97d005a879ecdaa16fd29ae434fb67b177c5e875b0c829e6a1db04"
var rk = generate_rk_from_ask(sk, alpha)
console.log("rk " + rk)

var spend_auth_sig = generate_spend_auth_sig(sk, alpha, msg)
console.log("spend authority signature " + spend_auth_sig)

var verify_spend_auth_sig_res = verify_spend_auth_sig(rk, msg, spend_auth_sig)
console.log("verify spend authority signature " + verify_spend_auth_sig_res)

//test data from tron api
console.log("__________________test data from tron api________________________")
var spend_auth_sig_test = "377d129cfff26177c7c7bba7a0e811b4705e59fdb65358daee067b07ffb89466942034fdfa3a7c06b9a635c401f550e08c9e387c59d8c63b8623f6cf388dbc02"
var alpha_test = "2608999c3a97d005a879ecdaa16fd29ae434fb67b177c5e875b0c829e6a1db04"
var ask_test = "e3ebcba1531f6d9158d9c162660c5d7c04dadf77d85d7436a9c98b291ff69a09"
var msg_hash = "3b78fee6e956f915ffe082284c5f18640edca9c57a5f227e5f7d7eb65ad61502"
var rk_test = generate_rk_from_ask(ask_test, alpha_test)
console.log("verify spend authority signature test " + verify_spend_auth_sig(rk_test, msg_hash, spend_auth_sig_test))

//generate keys and address
var keys = generate_keys()
console.log(keys)
console.log("sk: " + keys["sk"])
console.log("payment_address: " + keys["payment_address"])
console.log("__________________________________________")

var spending_key = "675e93f52880adff41940dbd26e3562288a2bde5fee820157e4b14e0d5ebddd5"
var keys_from_sk = generate_keys_by_sk(spending_key)
console.log(keys_from_sk)
console.log("__________________________________________")

var d = "0102030405060708090a0b"
var keys_from_sk_d = generate_keys_by_sk_d(spending_key, d)
console.log(keys_from_sk_d)
