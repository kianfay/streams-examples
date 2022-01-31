// https://github.com/iotaledger/identity.rs/blob/dev/examples/low-level-api/private_tangle.rs

use identity::{
    prelude::*,
    iota::{
        ClientBuilder, Network, Receipt, DIDMessageEncoding, ExplorerUrl, IotaDID
    }
};

// uploads the did for this user and returns the keypair and the DID id
pub async fn create_and_upload_did() -> Result<Option<(KeyPair, IotaDocument)>> {
    
    let network_name = "dev";
    let network = Network::try_from_name(network_name)?;
  
    // hardcoded as this fn will only ever be used on the private tangle
    let explorer = ExplorerUrl::parse("http://127.0.0.1:8082")?;
    let private_node_url = "http://127.0.0.1:14265";
  
    let encoding = DIDMessageEncoding::JsonBrotli;
    let client = ClientBuilder::new()
      .network(network.clone())
      .encoding(encoding)
      .primary_node(private_node_url, None, None)?
      .build()
      .await?;
    
    // generate a keypair and use to generate DID document and sign it
    let keypair: KeyPair = KeyPair::new_ed25519()?;
    let mut document: IotaDocument = IotaDocument::new_with_options(&keypair, Some(client.network().name()), None)?;
    document.sign_self(keypair.private(), &document.default_signing_method()?.id())?;
  
    // publish the DID Document to the Tangle.
    let receipt: Receipt = match client.publish_document(&document).await {
      Ok(receipt) => receipt,
      Err(err) => {
        eprintln!("Error > {:?}", err);
        eprintln!("Is your private Tangle node listening on {}?", private_node_url);
        return Ok(None);
      }
    };
  
    // prints the Identity Resolver Explorer URL, the entire history can be observed on this page by "Loading History".
    println!("Publish Receipt > {:#?}", receipt);
    println!(
      "[Example] Explore the DID Document = {}",
      explorer.resolver_url(document.id())?
    );

    return Ok(Some((keypair,document)))
}