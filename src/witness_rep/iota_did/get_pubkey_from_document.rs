use identity::account::{Account, Result};
use serde_json::{from_str, to_string, Value};

// returns the public key as a string
pub async fn get_pubkey_from_document(acc: &Account) -> Result<String> {
    let did = acc.resolve_identity().await?;
    let did_str = to_string(&did).unwrap();
    let did_val : Value = from_str(&did_str).unwrap();

    let capability_invocation_arr = did_val.get("doc")
                                .and_then(|value| value.get("capabilityInvocation"))
        /*                         .and_then(|value| value.get("publicKeyMultibase"))
                                .and_then(|value| value.as_str()) */
                                .unwrap();
    
    let pubkey = capability_invocation_arr[0].get("publicKeyMultibase")
                                           .and_then(|value| value.as_str())
                                           .unwrap();

    println!("pubkey: {}", pubkey);

    return Ok(did.to_string());
}