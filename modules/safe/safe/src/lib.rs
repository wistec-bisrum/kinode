use anyhow::Result;
use uqbar_process_lib::{ await_message, call_init, println, Address, Message, };
use uqbar_process_lib::eth::EthAddress;
use std::collections::{ HashMap, HashSet, };

wit_bindgen::generate!({
    path: "../../../wit",
    world: "process",
    exports: {
        world: Component,
    },
});

call_init!(init);

struct SafeUser {
    user: Address,
    wallet: EthAddress,
}

struct SafeTx {
    to: EthAddress,
    value: u64,
    data: Vec<u8>,
    operation: u8,
    safe_tx_gas: u64,
    base_gas: u64,
    gas_price: u64,
    gas_token: Address,
    refund_receiver: Address,
    nonce: u64,
}

struct Safe {
    signers: Vec<SafeUser>,
    delegates: Vec<SafeUser>,
    txs: HashMap<u64, SafeTx>,
    tx_sigs: HashMap<u64, Vec<u8>>,
}

struct State {
    safes: HashMap<EthAddress, Safe>,
    peers: HashSet<Address>,
}

fn init (our: Address) {

    println!("Hello from Safe! {:?}", our);

    loop {
        match await_message() {
            Err(e) => {
                println!("Error: {:?}", e);
                continue;
            }
            Ok(msg) => match handle_request(&our, &msg) {
                Ok(()) => continue,
                Err(e) => println!("Error: {:?}", e),
            },
        }
    }

}

fn handle_request(our: &Address, message: &Message) -> anyhow::Result<()> {

    println!("message: {:?}", message);
    Ok(())

}