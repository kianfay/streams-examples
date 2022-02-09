use anyhow::Result;

mod examples;
mod witness_rep;

#[tokio::main]
async fn main() -> Result<()> {
    let url = "http://0.0.0.0:14265";

/*     println!("Starting Examples");
    println!("---------------------------------------");
    println!("Single Publisher Examples");

    println!("\n---------------------------------------");
    println!("\nPublic - Single Branch - Single Publisher\n");
    examples::single_branch_public::example(url).await?; */

/*     println!("\n---------------------------------------");
    println!("\nPrivate - Single Branch - Single Publisher\n");
    examples::single_branch_private::example(url).await?; */

/*    println!("\n---------------------------------------");
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
/* 
    let annoucement_msg: String = String::from("50f2e2d30c543c95104b7c29d39a14f291d3977568e99c474271fade7780cdd90000000000000000:faab108c4804d112ba05abfa");
    witness_rep::verify_tx::verify_tx(url, annoucement_msg).await?; */

    println!("\n---------------------------------------");
    println!("\nTransaction simulation\n");
    //let annoucement_msg: String = String::from("a376d6da38e379e3968e94962dc56f5e6df9592795c93f024d34146d1f80b6650000000000000000:68986e7c6a600fad0cb57fe0");
    let annoucement_msg: String = witness_rep::all_in_one_transaction::transact(url).await?;
    println!("\nTransaction verification\n");
    witness_rep::utility::verify_tx::verify_txs(url, annoucement_msg).await?;
    //witness_rep::utility::verify_tx::testing()?;

    /* witness_rep::verify_tx::testing_sigs(); */


/*     let annoucement_msg: String = witness_rep::all_in_one_transaction::transact(url).await?;
    println!("\nTransaction verification\n");
    witness_rep::verify_tx::verify_tx(url, annoucement_msg).await?; */

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
