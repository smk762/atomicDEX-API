contract type ERC = sig

  type storage

  val%entry transfer: address * nat -> storage -> operation list * storage
  
  val%entry approve: address * nat -> storage -> operation list * storage                                            
  
  val%entry transferFrom: address * address * nat -> storage -> operation list * storage
    
  val%entry createAccount: address * nat -> storage -> operation list * storage                                                            
                                             
  val%entry createAccounts: (address * nat) list -> storage -> operation list * storage 
                                                               
end

type swap_state =
  | Initialized 
  | ReceiverSpent
  | SenderRefunded

type atomic_swap =
  {
    amount: tez;
    amount_nat: nat;
    contract_address: address option;
    lock_time: timestamp;
    receiver: address;
    secret_hash: bytes;
    sender: address;
    state: swap_state;
    uuid: bytes 
  }
type storage = {
  swaps: (bytes, atomic_swap) big_map;
  field: unit;
}

let%init storage = {
  swaps = BigMap;
  field = ();
}

let%entry init_tezos_swap (uuid, lock_time, secret_hash, receiver) storage =
  if Bytes.length secret_hash <> 32p then
    failwith "Secret hash length must be 32";
  if (Current.amount ()) <= 0tz then
    failwith "Transaction amount must be greater than zero";
  let new_swap =
    match Map.find uuid storage.swaps with
    | None -> {
        amount = Current.amount ();
        amount_nat = 0p;
        contract_address = None;
        lock_time;
        receiver;
        secret_hash;
        sender = Current.source ();
        state = Initialized;
        uuid;
      }
    | Some _ -> failwith "Swap was initialized already" in

  let new_swaps = Map.add uuid new_swap storage.swaps in
  [], storage.swaps <- new_swaps

let%entry init_erc_swap (uuid, lock_time, secret_hash, receiver, amount, contract_addr) storage =
  if Current.amount () > 0tz then
    failwith "Tx amount must be zero";
  if Bytes.length secret_hash <> 32p then
    failwith "Secret hash length must be 32";
  if amount <= 0p then
    failwith "ERC amount must be greater than zero";
  let new_swap =
    match Map.find uuid storage.swaps with
    | None -> {
        amount = Current.amount ();
        amount_nat = amount;
        contract_address = (Some contract_addr);
        lock_time;
        receiver;
        secret_hash;
        sender = Current.source ();
        state = Initialized;
        uuid;
      }
    | Some _ -> failwith "Swap was initialized already" in

  let my_address = Contract.address (Contract.self ()) in
  let new_swaps = Map.add uuid new_swap storage.swaps in
  let op = match (Contract.at contract_addr : ERC.instance option) with
    | None -> failwith ("Cannot recover erc contract from:", contract_addr)
    | Some my_contract -> my_contract.transferFrom (Current.source (), my_address, amount) ~amount:0tz
  in
  [op], storage.swaps <- new_swaps

let%entry receiver_spends (uuid, secret, send_to) storage =
  if Bytes.length secret <> 32p then
    failwith "Secret length must be 32";
  if Current.amount () > 0tz then
    failwith "Tx amount must be zero";
  let swap =
    match Map.find uuid storage.swaps with
    | None  -> failwith "Swap was not initialized"
    | Some swap -> match swap.state with
      | Initialized () -> swap
      | _ -> failwith "Swap must be in initialized state"
  in

  if Current.source () <> swap.receiver then
    failwith "Tx must be sent from receiver address";
  if Crypto.sha256 secret <> swap.secret_hash then
    failwith "Invalid secret";

  let swap = swap.state <- ReceiverSpent in
  let op = match swap.contract_address with
    | None -> Account.transfer ~dest:send_to ~amount:swap.amount
    | Some contract_addr -> match (Contract.at contract_addr : ERC.instance option) with
      | None -> failwith ("Cannot recover erc contract from:", contract_addr)
      | Some my_contract -> my_contract.transfer (swap.receiver, swap.amount_nat) ~amount:0tz
  in

  let new_swaps = Map.update uuid (Some swap) storage.swaps in
  [op], storage.swaps <- new_swaps

let%entry sender_refunds (uuid, send_to) storage =
  if Current.amount () > 0tz then
    failwith "Tx amount must be zero";
  let swap =
    match Map.find uuid storage.swaps with
    | None  -> failwith "Swap was not initialized"
    | Some swap -> match swap.state with
      | Initialized () -> swap
      | _ -> failwith "Swap must be in initialized state"
  in

  if Current.time () <= swap.lock_time then
    failwith "Too early to refund";

  if Current.source () <> swap.sender then
    failwith "Tx must be sent from sender address";

  let swap = swap.state <- SenderRefunded in
  let op = match swap.contract_address with
    | None -> Account.transfer ~dest:send_to ~amount:swap.amount
    | Some contract_addr -> match (Contract.at contract_addr : ERC.instance option) with
      | None -> failwith ("Cannot recover erc contract from:", contract_addr)
      | Some my_contract -> my_contract.transfer (swap.sender, swap.amount_nat) ~amount:0tz
  in

  let new_swaps = Map.update uuid (Some swap) storage.swaps in
  [op], storage.swaps <- new_swaps
