use anyhow::Result;

mod examples;
mod witness_rep;

use crate::witness_rep::iota_did::create_and_upload_did::create_n_dids;
use identity::crypto::PublicKey as IdPub;

#[tokio::main]
async fn main() -> Result<()> {
    let url = "http://0.0.0.0:14265";

    /* println!("Starting Examples");
    println!("---------------------------------------");
    println!("Single Publisher Examples");

    println!("\n---------------------------------------");
    println!("\nPublic - Single Branch - Single Publisher\n");
    examples::single_branch_public::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nPrivate - Single Branch - Single Publisher\n");
    examples::single_branch_private::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nPublic - Single Depth - Single Publisher\n");
    examples::single_depth_public::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nPrivate - Single Depth - Single Publisher\n");
    examples::single_depth_private::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nMixed - Multi Branch - Single Publisher\n");
    examples::multi_branch_mixed_privacy::example(url).await?;

    println!("\n---------------------------------------");
    println!("Multiple Publisher Examples");

    println!("\n---------------------------------------");
    println!("\nPrivate - Multi Branch - Single Publisher per Branch\n");
    examples::single_pub_per_branch::example(url).await?; */

/*     println!("\n---------------------------------------");
    println!("\nPrivate - Multi Branch - Multiple Publishers per Branch\n");
    examples::multi_pub_per_branch::example(url).await?; */

/*     println!("\n---------------------------------------");
    println!("\nTransaction simulation\n");
    witness_rep::all_in_one_transaction::transact(url).await?;
 */
use crate::witness_rep::iota_did::create_and_upload_did::Key;
use identity::{
    iota::IotaDocument,
    did::MethodData,
    crypto::KeyPair
};

let did_details = create_n_dids(1).await?;
    
let mut did_pubkeys : Vec<&Key> = did_details
                                        .iter()
                                        .map(|(_, (_,(_,pubk)), _)| pubk)
                                        .collect();

let mut did_privkeys : Vec<&Key> = did_details
                                        .iter()
                                        .map(|(_, (_,(privk,_)), _)| privk)
                                        .collect();

let mut did_docs : Vec<&IotaDocument> = did_details
                                        .iter()
                                        .map(|(doc, _, _)| doc)
                                        .collect();

let mut did_kps : Vec<&KeyPair> = did_details
                                        .iter()
                                        .map(|(_, (kp,_), _)| kp)
                                        .collect();


let multibase_pub = MethodData::new_multibase(did_kps[0].public());

if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
    println!("{}",mbpub);
}

/* 
    println!("\n---------------------------------------");
    println!("Utility Examples");

    println!("\n---------------------------------------");
    println!("\nPrevious Message Retrieval\n");
    examples::fetch_prev::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nGranting and Revoking Access\n");
    examples::grant_and_revoke_access::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nUsing Public Keys for Keyload Generation\n");
    examples::pk_keyloads::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nUsing Pre Shared Keys for Keyload Generation\n");
    examples::psk_keyloads::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nState Recovery\n");
    examples::state_recovery::example(url).await?;

    println!("\n---------------------------------------");
    println!("\nStateless Recovery\n");
    examples::stateless_recovery::example(url).await?; */

    println!("\n---------------------------------------");
    println!("Examples Complete");

    Ok(())
}
