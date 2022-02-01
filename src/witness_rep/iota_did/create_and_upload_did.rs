use identity::{
    iota::{ClientBuilder, DIDMessageEncoding, ExplorerUrl, Network, IotaDID},
    prelude::*,
    account::{Account, AccountStorage, IdentitySetup, Result}
};
use std::path::PathBuf;

// https://github.com/iotaledger/identity.rs/blob/dev/examples/low-level-api/private_tangle.rs

pub async fn create_n_dids(n: u16) -> Result<Vec<(Account, String)>> {
    let mut did_array = Vec::new();
    for i in 0..n {
        let stronghold_path = format!("./example-strong{}.hodl",i);
        let stronghold_path_2 = format!("./example-strong{}.hodl",i);
        let extracted_did = create_and_upload_did(stronghold_path).await?;
        match extracted_did {
            Some(v) => did_array.push((v,stronghold_path_2)),
            None    => {
                panic!(format!("The DID at index {} failed", i));
            },
        }
    }
    return Ok(did_array);
}

// uploads the did for this user and returns the Account object
async fn create_and_upload_did(stronghold_relative_path: String) -> Result<Option<Account>> {
    let network_name = "dev";
    let network = Network::try_from_name(network_name)?;

    // hardcoded as this fn will only ever be used on the private tangle
    let explorer = ExplorerUrl::parse("http://127.0.0.1:8082")?;
    let private_node_url = "http://127.0.0.1:14265";
    let encoding = DIDMessageEncoding::JsonBrotli;
    let client_builder = ClientBuilder::new()
        .network(network.clone())
        .encoding(encoding)
        .primary_node(private_node_url, None, None)?;

    // we try to build an account object using client
    let stronghold_path: PathBuf = stronghold_relative_path.into();
    let password: String = "my-password".into();
    let stronghold = AccountStorage::Stronghold(stronghold_path, Some(password), None);

    let account: Account = Account::builder()
        .client_builder(client_builder)
        .storage(stronghold)
        .create_identity(IdentitySetup::default())
        .await?;

    // Retrieve the did of the newly created identity.
    let iota_did: &IotaDID = account.did();

    // Print the local state of the DID Document
    println!("[Example] Local Document from {} = {:#?}", iota_did, account.document());

    // Prints the Identity Resolver Explorer URL.
    // The entire history can be observed on this page by clicking "Loading History".
    let explorer: &ExplorerUrl = ExplorerUrl::mainnet();
    println!(
    "[Example] Explore the DID Document = {}",
    explorer.resolver_url(iota_did)?
    );

    return Ok(Some(account));
}
