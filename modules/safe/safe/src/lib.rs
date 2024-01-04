use anyhow::Result;
use serde::{Deserialize, Serialize, };
use std::collections::HashSet;
use std::collections::hash_map::{ Entry, HashMap, };
use uqbar_process_lib::{ 
    await_message, call_init, get_payload, http, println, set_state,
    Address, Message, NodeId, Request
};
use uqbar_process_lib::eth::EthAddress;

wit_bindgen::generate!({
    path: "../../../wit",
    world: "process",
    exports: {
        world: Component,
    },
});

call_init!(init);


#[derive(Clone, Serialize, Deserialize, Debug)]
enum SafeActions {
    AddSafe(AddSafe),
    AddPeer(AddPeer)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct AddPeer {
    safe: EthAddress,
    peer: NodeId,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct AddSafe {
    safe: EthAddress,
}

#[derive(Clone, Serialize, Deserialize)]
struct SafeUser {
    user: NodeId,
    wallet: EthAddress,
}

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize, Default)]
struct Safe {
    peers: HashSet<NodeId>,
    signers: Vec<SafeUser>,
    delegates: Vec<SafeUser>,
    txs: HashMap<u64, SafeTx>,
    tx_sigs: HashMap<u64, Vec<u8>>,
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct State {
    safes: HashMap<EthAddress, Safe>,
}

fn init (our: Address) {

    let mut state = State {
        safes: HashMap::new(),
    };

    http::bind_http_path("/", true, false).unwrap();
    http::bind_http_path("/safe", true, false).unwrap();
    http::bind_http_path("/safe/delegate", true, false).unwrap();
    http::bind_http_path("/safe/peer", true, false).unwrap();
    http::bind_http_path("/safe/send", true, false).unwrap();
    http::bind_http_path("/safe/signer", true, false).unwrap();
    http::bind_http_path("/safes", true, false).unwrap();
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
        let _ = set_state(&bincode::serialize(&state).unwrap());
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
        msg.source().process == "http_server:sys:uqbar" {
            handle_http_request(our, msg, state);
    }

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
            println!("websocket open!, {}, {}", path, channel_id);
            Ok(())
        }
        http::HttpServerRequest::WebSocketClose (channel_id) => {
            println!("websocket close");
            Ok(())
        }
        http::HttpServerRequest::WebSocketPush { .. } => {
            println!("websockets push");
            Ok(())
        }
        _ => {
            println!("mysterious");
            Ok(())
        }
    }

}

fn handle_http_methods(
    our: &Address, 
    state: &mut State, 
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {

    if let Ok(path) = http_request.path() {
        println!("http path: {:?}, method: {:?}", path, http_request.method);
        match &path[..] {
            "" => handle_http_slash(our, state, http_request),
            "safe" => handle_http_safe(our, state, http_request),
            "safes" => handle_http_safes(our, state, http_request),
            "safe/delegate" => handle_http_safe_delegate(our, state, http_request),
            "safe/peer" => handle_http_safe_peer(our, state, http_request),
            "safe/send" => handle_http_safe_send(our, state, http_request),
            "safe/signer" => handle_http_safe_signer(our, state, http_request),
            &_ => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![])
        }
    } else {
        Ok(())
    }

}

fn handle_http_slash(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {

    match http_request.method.as_str() {
        // on GET: give the frontend all of our active games
        "GET" => {
            println!("GET!");
            http::send_response(http::StatusCode::OK, None, vec![]);
            Ok(())
        }
        "POST" => {
            println!("POST!");
            Ok(())
        }
        "PUT" => {
            println!("PUT!");
            Ok(())
        }
        "DELETE" => {
            println!("DELETE!");
            Ok(())
        }
        _ => {
            http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
            Ok(())
        }
    }

}

fn handle_http_safe(
    our: &Address, 
    state: &mut State, 
    http_request: &http::IncomingHttpRequest
) -> anyhow::Result<()> { 
    match http_request.method.as_str() {
        // on GET: give the frontend all of our active games
        "GET" => {
            println!("GET!");
            http::send_response(http::StatusCode::OK, None, vec![]);
            Ok(())
        }
        "POST" => {
            let Some(payload) = get_payload() else {
                return http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
            };

            let AddSafe{ safe } = serde_json::from_slice::<AddSafe>(&payload.bytes)?;

            match state.safes.entry(safe) {
                Entry::Vacant(v) => {
                    v.insert(Safe::default());
                    http::send_response(http::StatusCode::OK, None, vec![]);
                }
                Entry::Occupied(_) => {
                    http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
                }
            }

            Ok(())
        }
        "PUT" => {
            println!("PUT!");
            Ok(())
        }
        "DELETE" => {
            println!("DELETE!");
            Ok(())
        }
        _ => {
            http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
            Ok(())
        }
    }

}

fn handle_http_safes(
    our: &Address, 
    state: &mut State, 
    http_request: &http::IncomingHttpRequest
) -> anyhow::Result<()> { 
    match http_request.method.as_str() {
        "GET" => http::send_response(http::StatusCode::OK, None, serde_json::to_vec(&state.safes)?),
        _ => http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![])
    }
}

fn handle_http_safe_peer(
    our: &Address, 
    state: &mut State, 
    http_request: &http::IncomingHttpRequest
) -> anyhow::Result<()> { 
    println!("safe peer {}", http_request.method.as_str());
    match http_request.method.as_str() {
        "POST" => {
            let payload = get_payload().unwrap();

            let AddPeer{ peer, safe } = serde_json::from_slice::<AddPeer>(&payload.bytes)?;

            match state.safes.entry(safe) {
                Entry::Vacant(_) => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]),
                Entry::Occupied(mut o) => {
                    let saved_safe = o.get_mut();
                    match saved_safe.peers.contains(&peer) {
                        true => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]),
                        false => {
                            saved_safe.peers.insert(peer.clone());
                            Request::new()
                                .target(Address{node:peer, process:our.process.clone()})
                                .ipc(serde_json::to_vec(&AddSafe{ safe })?)
                                .send()?;
                            http::send_response(http::StatusCode::OK, None, vec![])
                        }
                    }
                }
            };
        }
        _ => {
            http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
        }
    }
    Ok(()) 
}

fn handle_http_safe_delegate(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }
fn handle_http_safe_send(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }
fn handle_http_safe_signer(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }