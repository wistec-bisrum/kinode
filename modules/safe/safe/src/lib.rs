use anyhow::Result;
use uqbar_process_lib::{ 
    await_message, call_init, http, println, 
    Address, Message, 
};
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

    let mut state = State {
        safes: HashMap::new(),
        peers: HashSet::new(),
    };

    http::bind_http_path("/", true, false).unwrap();
    http::bind_ws_path("/", true, false).unwrap();

    println!("Hello from Safe! {:?}", our);

    loop {
        match await_message() {
            Err(e) => {
                println!("Error: {:?}", e);
                continue;
            }
            Ok(msg) => match handle_request(&our, &msg, &mut state) {
                Ok(()) => continue,
                Err(e) => println!("Error: {:?}", e),
            },
        }
    }

}

fn handle_request(our: &Address, msg: &Message, state: &mut State) -> anyhow::Result<()> {

    if !msg.is_request() {
        return Ok(());
    }

    if msg.source().node != our.node {
        handle_p2p_request(msg);
    } else if
        msg.source().node == our.node && 
        msg.source().process == "terminal:terminal:uqbar" {
            handle_terminal_request(msg);

    } else if 
        msg.source().node == our.node &&
        msg.source().process == "http:sys:uqbar" {
            handle_http_request(our, msg, state);

    }

    println!("message: {:?}", msg);

    Ok(())

}

fn handle_p2p_request(msg: &Message) -> anyhow::Result<()> {
    println!("p2p message: {:?}", msg);
    Ok(())
}

fn handle_terminal_request(msg: &Message) -> anyhow::Result<()> {
    println!("terminal message: {:?}", msg);
    Ok(())
}

fn handle_http_request(our: &Address, msg: &Message, state: &mut State) -> anyhow::Result<()> {
    println!("http message: {:?}", msg);

    match serde_json::from_slice::<http::HttpServerRequest>(msg.ipc())? {
        http::HttpServerRequest::Http(ref incoming) => {
            match handle_http_methods(our, state, incoming) {
                Ok(()) => Ok(()),
                Err(e) => {
                    http::send_response(
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        None,
                        "Service Unavailable".to_string().as_bytes().to_vec(),
                    )
                }
            }
        }
        http::HttpServerRequest::WebSocketOpen { path, channel_id } => {
            Ok(())
        }
        http::HttpServerRequest::WebSocketClose(channel_id) => {
            Ok(())
        }
        http::HttpServerRequest::WebSocketPush { .. } => Ok(())
    }

}

fn handle_http_methods(
    our: &Address, 
    state: &mut State, 
    http_request: &http::IncomingHttpRequest
) -> anyhow::Result<()> {

    match http_request.method.as_str() {
        // on GET: give the frontend all of our active games
        "GET" => Ok(()),
        "POST" => Ok(()),
        "PUT" => Ok(()),
        "DELETE" => Ok(()),
        _ => http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]),
    };
    Ok(())

}