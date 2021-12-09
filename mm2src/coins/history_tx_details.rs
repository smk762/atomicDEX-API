use crate::TransactionDetails;
use common::mm_number::BigDecimal;
use std::collections::{HashMap, HashSet};

pub struct Builder<Addr, Tx> {
    tx: Tx,
    my_addresses: HashSet<Addr>,
    total_amount: BigDecimal,
    received_by_me: BigDecimal,
    spent_by_me: BigDecimal,
    from_addresses: HashSet<Addr>,
    to_addresses: HashSet<Addr>,
    amounts_transferred: HashMap<Addr, BigDecimal>,
}

impl<Addr: Clone + Eq + std::hash::Hash, Tx> Builder<Addr, Tx> {
    pub fn new(tx: Tx) -> Self {
        Builder {
            tx,
            my_addresses: Default::default(),
            total_amount: Default::default(),
            received_by_me: Default::default(),
            spent_by_me: Default::default(),
            from_addresses: Default::default(),
            to_addresses: Default::default(),
            amounts_transferred: Default::default(),
        }
    }

    pub fn transferred_to(&mut self, address: Addr, amount: &BigDecimal) {
        if self.my_addresses.contains(&address) {
            self.received_by_me += amount;
        }
        self.to_addresses.insert(address.clone());
        *self.amounts_transferred.entry(address).or_insert(BigDecimal::from(0)) += amount;
    }

    pub fn transferred_from(&mut self, address: Addr, amount: &BigDecimal) {
        if self.my_addresses.contains(&address) {
            self.spent_by_me += amount;
        }
        self.total_amount += amount;
        self.from_addresses.insert(address.clone());
        *self.amounts_transferred.entry(address).or_insert(BigDecimal::from(0)) -= amount;
    }

    pub fn build(self) -> TransactionDetails { unimplemented!() }
}
