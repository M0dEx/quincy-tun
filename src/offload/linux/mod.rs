//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use etherparse::IpHeaders;

use crate::{Error, Result};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;

mod checksum;
mod coalesce;
mod packet;
mod tcp;
mod udp;
mod virtio;

const IDEAL_BATCH_SIZE: usize = 128;

trait IpAddress {
    fn src_addr(&self) -> IpAddr;
    fn dst_addr(&self) -> IpAddr;
}

pub(crate) struct GroTable<K, T> {
    items_by_flow: HashMap<K, Vec<T>>,
}

impl IpAddress for IpHeaders {
    fn src_addr(&self) -> IpAddr {
        match self {
            IpHeaders::Ipv4(header, _) => header.source.into(),
            IpHeaders::Ipv6(header, _) => header.source.into(),
        }
    }

    fn dst_addr(&self) -> IpAddr {
        match self {
            IpHeaders::Ipv4(header, _) => header.destination.into(),
            IpHeaders::Ipv6(header, _) => header.destination.into(),
        }
    }
}

impl<K: Copy + Hash + Eq, T> GroTable<K, T> {
    pub(crate) fn new() -> Self {
        Self {
            items_by_flow: HashMap::with_capacity(IDEAL_BATCH_SIZE),
        }
    }

    /// Get an items Vec from the table (or create a new one if it does not exist)
    pub(crate) fn get(&mut self, key: K) -> &mut Vec<T> {
        self.items_by_flow
            .entry(key)
            .or_insert(Vec::with_capacity(IDEAL_BATCH_SIZE))
    }

    /// Updates the item for the given flow at the given index.
    pub(crate) fn update_at(&mut self, key: &K, index: usize, item: T) -> Result<()> {
        *self
            .items_by_flow
            .get_mut(key)
            .ok_or(Error::OffloadFlowNotFound)?
            .get_mut(index)
            .ok_or(Error::OffloadFlowNotFound)? = item;

        Ok(())
    }

    /// Deletes the item for the given flow at the given index.
    pub(crate) fn delete_at(&mut self, key: &K, index: usize) -> Result<()> {
        self.items_by_flow
            .get_mut(key)
            .map(|items| items.remove(index))
            .ok_or(Error::OffloadFlowNotFound)?;

        Ok(())
    }

    /// Clears the table.
    pub(crate) fn clear(&mut self) {
        self.items_by_flow.clear();
    }
}
