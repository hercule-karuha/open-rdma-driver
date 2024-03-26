use std::{
    collections::{HashMap, LinkedList},
    sync::{mpsc::Sender, Arc, Mutex, RwLock},
};

use crate::{
    op_ctx::ReadOpCtx,
    recv_pkt_map::RecvPktMap,
    responser::{RespAckCommand, RespCommand},
    types::{Msn, Psn},
};

pub(crate) struct PacketChecker {
    _thread: std::thread::JoinHandle<()>,
}

impl PacketChecker {
    pub fn new(
        send_queue: Sender<RespCommand>,
        recv_pkt_map: Arc<RwLock<HashMap<Msn, Arc<Mutex<RecvPktMap>>>>>,
        read_op_ctx_map: Arc<RwLock<HashMap<Msn, ReadOpCtx>>>,
    ) -> Self {
        let ctx = PacketCheckerContext {
            send_queue,
            recv_pkt_map,
            read_op_ctx_map,
        };
        let thread = std::thread::spawn(move || {
            PacketCheckerContext::working_thread(ctx);
        });
        Self { _thread: thread }
    }
}

struct PacketCheckerContext {
    send_queue: Sender<RespCommand>,
    recv_pkt_map: Arc<RwLock<HashMap<Msn, Arc<Mutex<RecvPktMap>>>>>,
    read_op_ctx_map: Arc<RwLock<HashMap<Msn, ReadOpCtx>>>,
}

enum ThreadFlag {
    Running,
    Stopped(&'static str),
}

impl PacketCheckerContext {
    fn working_thread(ctx: Self) {
        loop {
            match ctx.check_pkt_map() {
                ThreadFlag::Running => {}
                ThreadFlag::Stopped(reason) => {
                    eprintln!("PacketChecker stopped: {}", reason);
                    break;
                }
            }
        }
    }
    fn check_pkt_map(&self) -> ThreadFlag {
        let mut remove_list = LinkedList::new();
        let iter_maps = {
            let guard = self.recv_pkt_map.read().unwrap();
            guard
                .iter()
                .map(|(k, v)| (*k, Arc::clone(v)))
                .collect::<Vec<_>>()
        };
        for (msn, map) in iter_maps.into_iter() {
            let (is_complete, is_read_resp, is_out_of_order, dqpn, end_psn) = {
                let guard = map.lock().unwrap();
                (
                    guard.is_complete(),
                    guard.is_read_resp(),
                    guard.is_out_of_order(),
                    guard.dqpn(),
                    guard.end_psn(),
                )
            };
            // send ack
            if is_complete {
                println!("Complete: {:?}", &msn);
                if !is_read_resp {
                    // If we are not in read response, we should send ack
                    let command = RespCommand::Acknowledge(RespAckCommand::new_ack(
                        dqpn,
                        msn,
                        end_psn,
                    ));
                    if self.send_queue.send(command).is_err() {
                        eprintln!("Failed to send ack command");
                        return ThreadFlag::Stopped("Send queue is broken");
                    }
                }else if let Some(ctx) = self.read_op_ctx_map.read().unwrap().get(&msn) {
                    ctx.set_result(());
                }else{
                    eprintln!("No read op ctx found for {:?}", msn);
                }
                remove_list.push_back(msn);
            } else if is_out_of_order {
                // TODO: what should we put in NACK packet?
                let command = RespCommand::Acknowledge(RespAckCommand::new_nack(
                    dqpn,
                    Msn::default(),
                    end_psn,
                    Psn::default(),
                ));
                if self.send_queue.send(command).is_err() {
                    eprintln!("Failed to send nack command");
                    return ThreadFlag::Stopped("Send queue is broken");
                }
                panic!("send nack command")
            }

            // everthing is fine, do nothing
        }

        // remove the completed recv_pkt_map
        if !remove_list.is_empty() {
            let mut guard = self.recv_pkt_map.write().unwrap();
            remove_list.iter().for_each(|dqpn| {
                guard.remove(dqpn);
            });
        }
        ThreadFlag::Running
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{mpsc, Mutex},
        thread::sleep,
        time::Duration,
    };

    use crate::{
        recv_pkt_map::RecvPktMap,
        types::{Msn, Psn, Qpn},
    };

    use super::PacketChecker;

    #[test]
    fn test_packet_checker() {
        let (send_queue, recv_queue) = mpsc::channel();
        let recv_pkt_map =
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let read_op_ctx_map =
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let _packet_checker =
            PacketChecker::new(send_queue, recv_pkt_map.clone(), read_op_ctx_map.clone());
        let key = Msn::new(1);
        recv_pkt_map.write().unwrap().insert(
            key,
            Mutex::new(RecvPktMap::new(false, 2, Psn::new(1), Qpn::new(3))).into(),
        );
        recv_pkt_map
            .write()
            .unwrap()
            .get(&key)
            .unwrap()
            .lock()
            .unwrap()
            .insert(Psn::new(1));
        sleep(Duration::from_millis(1));
        assert!(matches!(
            recv_queue.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        recv_pkt_map
            .write()
            .unwrap()
            .get(&key)
            .unwrap()
            .lock()
            .unwrap()
            .insert(Psn::new(2));
        sleep(Duration::from_millis(10));
        assert!(recv_queue.try_recv().is_ok());
    }
}