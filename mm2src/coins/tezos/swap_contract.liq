contract type ERC = sig
  val%entry transfer: address * address * nat
end

type swap_state =
  | Initialized
  | ReceiverSpent
  | SenderRefunded

type secret_hash_algo =
  | Sha256
  | Sha512
  | Blake2b256

type atomic_swap =
  {
    amount: tez;
    amount_nat: nat;
    contract_address: address option;
    created_at: timestamp;
    lock_time: timestamp;
    receiver: address;
    secret_hash: bytes;
    secret_hash_type: secret_hash_algo;
    sender: address;
    spent_at: timestamp option;
    state: swap_state;
    uuid: bytes;
  }
type storage = {
  swaps: (bytes, atomic_swap) big_map;
  version: nat;
}

let%init storage = {
  swaps = BigMap;
  version = 1p;
}

let%entry default ( to_forward : dun ) _ =
  failwith ("Not implemented")

let%entry init_tezos_swap (uuid, lock_time, secret_hash, secret_hash_type, receiver) storage =
  let expected_len = match secret_hash_type with
    | Sha256 -> 32p
    | Sha512 -> 64p
    | Blake2b256 -> 32p
  in

  if Bytes.length secret_hash <> expected_len then
    failwith ("Secret hash length must be ", expected_len);

  if (Current.amount ()) <= 0tz then
    failwith "Transaction amount must be greater than zero";
  let new_swap =
    match Map.find uuid storage.swaps with
    | None -> {
        amount = Current.amount ();
        amount_nat = 0p;
        contract_address = None;
        created_at = Current.time ();
        lock_time;
        receiver;
        secret_hash;
        secret_hash_type;
        sender = Current.source ();
        spent_at = None;
        state = Initialized;
        uuid;
      }
    | Some _ -> failwith "Swap was initialized already" in

  let new_swaps = Map.add uuid new_swap storage.swaps in
  [], storage.swaps <- new_swaps

let%entry init_erc_swap (uuid, lock_time, secret_hash, secret_hash_type, receiver, amount, contract_addr) storage =
  if Current.amount () > 0tz then
    failwith "Tx amount must be zero";

  let expected_len = match secret_hash_type with
    | Sha256 -> 32p
    | Sha512 -> 64p
    | Blake2b256 -> 32p
  in

  if Bytes.length secret_hash <> expected_len then
    failwith ("Secret hash length must be ", expected_len);

  if amount <= 0p then
    failwith "ERC amount must be greater than zero";
  let new_swap =
    match Map.find uuid storage.swaps with
    | None -> {
        amount = Current.amount ();
        amount_nat = amount;
        contract_address = (Some contract_addr);
        created_at = Current.time ();
        lock_time;
        receiver;
        secret_hash;
        secret_hash_type;
        sender = Current.source ();
        spent_at = None;
        state = Initialized;
        uuid;
      }
    | Some _ -> failwith "Swap was initialized already" in

  let my_address = Contract.untype (Contract.self ()) in
  let new_swaps = Map.add uuid new_swap storage.swaps in
  let op = match [%handle ERC.transfer] contract_addr with
    | None -> failwith ("Cannot recover erc contract from:", contract_addr)
    | Some my_contract -> my_contract.transfer (Current.source (), my_address, amount) ~amount:0tz
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

  let hashed_secret = match swap.secret_hash_type with
    | Sha256 -> Crypto.sha256 secret
    | Sha512 -> Crypto.sha512 secret
    | Blake2b256 -> Crypto.blake2b secret
  in

  if hashed_secret <> swap.secret_hash then
    failwith "Invalid secret";

  let timestamp = Current.time () in
  let swap = swap.state <- ReceiverSpent in
  let swap = swap.spent_at <- (Some timestamp) in
  let my_address = Contract.untype (Contract.self ()) in

  let op = match swap.contract_address with
    | None -> Account.transfer ~dest:send_to ~amount:swap.amount
    | Some contract_addr -> match [%handle ERC.transfer] contract_addr with
      | None -> failwith ("Cannot recover erc contract from:", contract_addr)
      | Some my_contract -> my_contract.transfer (my_address, swap.receiver, swap.amount_nat) ~amount:0tz
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

  let timestamp = Current.time () in
  if  timestamp <= swap.lock_time then
    failwith "Too early to refund";

  if Current.source () <> swap.sender then
    failwith "Tx must be sent from sender address";

  let swap = swap.state <- SenderRefunded in
  let swap = swap.spent_at <- (Some timestamp) in
  let my_address = Contract.untype (Contract.self ()) in

  let op = match swap.contract_address with
    | None -> Account.transfer ~dest:send_to ~amount:swap.amount
    | Some contract_addr -> match [%handle ERC.transfer] contract_addr with
      | None -> failwith ("Cannot recover erc contract from:", contract_addr)
      | Some my_contract -> my_contract.transfer (my_address, swap.sender, swap.amount_nat) ~amount:0tz
  in

  let new_swaps = Map.update uuid (Some swap) storage.swaps in
  [op], storage.swaps <- new_swaps
