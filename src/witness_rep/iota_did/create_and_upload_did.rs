use identity::{
    iota::{ClientBuilder, DIDMessageEncoding, ExplorerUrl, Network, Client, ClientMap, Receipt, IotaDocument},
    account::{Result},
    crypto::KeyPair,
    core::Result as Res
};

use crypto::signatures::ed25519;
// https://github.com/iotaledger/identity.rs/blob/dev/examples/low-level-api/private_tangle.rs


pub type Key = [u8; 32];

// returns a tuple of the Account and the Stronghold file name
// in a practical setting, we would return the url and need to fetch it from the tangle
pub async fn create_n_dids(n: u16) -> Result<Vec<(IotaDocument,(KeyPair,(Key,Key)),Receipt)>> {
    let mut did_array = Vec::new();
    for _ in 0..n {
        let did_info = create_and_upload_did().await?;
        did_array.push(did_info);
    }
    return Ok(did_array);
}

// uploads the did for this user and returns the Account object
async fn create_and_upload_did() -> Result<(IotaDocument,(KeyPair,(Key,Key)),Receipt)> {
     let network_name = "dev";
    let network = Network::try_from_name(network_name)?;

    // hardcoded as this fn will only ever be used on the private tangle
    //let explorer = ExplorerUrl::parse("http://127.0.0.1:8082")?;
    let private_node_url = "http://127.0.0.1:14265";
    let encoding = DIDMessageEncoding::JsonBrotli;
    let client_builder = ClientBuilder::new()
        .network(network.clone())
        .encoding(encoding)
        .primary_node(private_node_url, None, None)?;
    
    let client = Client::from_builder(client_builder).await?;
    let client_map = ClientMap::from_client(client);

    // Generate a new Ed25519 public/private key pair.
    let (keypair, private_key) = gen_iota_keypair();

    // Create a DID Document (an identity) from the generated key pair.
    let mut document: IotaDocument = IotaDocument::new(&keypair)?;

    // Sign the DID Document with the default signing method.
    document.sign_self(keypair.private(), &document.default_signing_method()?.id())?;

    println!("DID Document JSON > {:#}", document);

    // Publish the DID Document to the Tangle.
    let receipt: Receipt = client_map.publish_document(&document).await?;

    println!("Publish Receipt > {:#?}", receipt);

    // Display the web explorer url that shows the published message.
    let explorer: &ExplorerUrl = ExplorerUrl::mainnet();
    println!(
        "DID Document Transaction > {}",
        explorer.message_url(receipt.message_id())?
    );
    println!("Explore the DID Document > {}", explorer.resolver_url(document.id())?);

    Ok((document, (keypair, private_key), receipt))
}

// returns a keypair and the associated private key
pub fn gen_iota_keypair() -> (KeyPair,(Key,Key)) {
    let sec_res = generate_ed25519_keypair();
    if let Ok((pubk,sec)) = sec_res {
        let kp_res = KeyPair::try_from_ed25519_bytes(&sec);
        if let Ok(kp) = kp_res {
            return (kp, (pubk,sec));
        }
        else {
            panic!("Failed to generate keypair");
        }
    }
    else {
        panic!("Failed to generate keypair");
    }
}

/// Generates a new pair of public/private Ed25519 keys.
///
/// Note that the private key is a 32-byte seed in compliance with [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032#section-3.2).
/// Other implementations often use another format. See [this blog post](https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/) for further explanation.
pub fn generate_ed25519_keypair() -> Res<(Key,Key)> {
    let secret_res = ed25519::SecretKey::generate();
    if let Ok(secret) = secret_res {
        let public: ed25519::PublicKey = secret.public_key();

        let private = secret.to_bytes();
        let public = public.to_bytes();
    
        Ok((public, private))
    }
    else {
        panic!("Failed to generate keypair");
    }
}