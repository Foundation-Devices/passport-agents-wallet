// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! USB CDC-ACM transport for Passport Prime hardware (`cfg(keyos)` only).
//!
//! Prime exposes a second CDC-ACM serial interface alongside KeyOS's boot-time
//! serial log port; the host (the `prime.py` HWI driver, `prime-signer`, or any
//! HWI-speaking wallet) reaches it over the host's serial API.
//!
//! Wire format: newline-delimited JSON, one `device_protocol::Request` per line,
//! one `device_protocol::Response` per line. Each line is dispatched through
//! `crate::process_request` - the SAME gated sign / xpub / showaddr handler the
//! file bridge uses on the simulator, so device and sim behave identically.
//!
//! USB API matched to `os/logging/usb-serial` (the v1.3 boot CDC service). NOTE:
//! registering a *second* CDC interface at runtime has hit a KeyOS USB-server
//! kernel bug before - validate at hardware bring-up.

use std::sync::{mpsc, Arc, Mutex};

use server::{handle_blocking_archive_message, BlockingArchiveHandler, MessageId, Server, ServerMessages};
use usb::device::{
    api::{EndpointDirection, EndpointType},
    messages::{EndpointProperties, SetupPacketCallback},
};

use crate::nunchuk::device_protocol::Response;
use crate::AppState;

usb::use_device_api!();

// --- USB descriptors --------------------------------------------------------

const IFCE_CDC_CLASS: u8 = 0x02; // CDC Communications Class
const IFCE_CDC_SUBCLASS: u8 = 0x02; // Abstract Control Model (virtual COM)
const IFCE_CDC_DATA_CLASS: u8 = 0x0A; // CDC Data Class (bulk companion)

const CTRL_ENDPOINTS: [EndpointProperties; 1] = [EndpointProperties {
    ep_type: EndpointType::Interrupt,
    ep_direction: EndpointDirection::In,
    max_packet_len: 64,
    interval: 16,
    use_dma: false,
}];

const DATA_ENDPOINTS: [EndpointProperties; 2] = [
    EndpointProperties {
        ep_type: EndpointType::Bulk,
        ep_direction: EndpointDirection::Out,
        max_packet_len: 512,
        interval: 0,
        use_dma: false,
    },
    EndpointProperties {
        ep_type: EndpointType::Bulk,
        ep_direction: EndpointDirection::In,
        max_packet_len: 512,
        interval: 0,
        use_dma: true,
    },
];

// --- Setup responder -------------------------------------------------------

/// CDC-ACM needs SetControlLineState + SetLineConfig acknowledged so hosts open
/// the port. Matches the v1.3 `usb-serial` BlockingArchiveHandler pattern.
#[derive(Default)]
struct SetupResponder {
    interface_num: u16,
}

impl ServerMessages for SetupResponder {
    const NAME: &str = "";
    fn messages() -> &'static [server::MessageDef<Self>]
    where
        Self: Sized,
    {
        &[(SetupPacketCallback::ID, handle_blocking_archive_message::<SetupPacketCallback, _>)]
    }
}
impl Server for SetupResponder {}
impl BlockingArchiveHandler<SetupPacketCallback> for SetupResponder {
    fn handle(
        &mut self,
        SetupPacketCallback(msg): SetupPacketCallback,
        _sender: xous::PID,
        _context: &mut server::ServerContext<Self>,
    ) -> Option<Vec<u8>> {
        // SetControlLineState (0x21/0x22) + SetLineConfig (0x21/0x20): accept + ignore.
        if msg.index == self.interface_num
            && msg.request_type == 0x21
            && (msg.request == 0x22 || msg.request == 0x20)
        {
            Some(Vec::new())
        } else {
            None
        }
    }
}

// --- Dispatch --------------------------------------------------------------

fn dispatch(state: &Arc<Mutex<AppState>>, payload: &[u8]) -> Response {
    match Response::parse_request(payload) {
        Ok(req) => crate::process_request(state, req),
        Err(resp) => resp,
    }
}

// --- Transport loop --------------------------------------------------------

/// Register the CDC-ACM interfaces and serve requests until the app exits.
/// Single-flight (one request, one response).
pub fn serve(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    let mut usb_api = UsbDeviceEmulation::default();
    let interface_num = usb_api.registered_interfaces() as u16;
    usb_api
        .register_setup_responder(SetupResponder { interface_num })
        .map_err(|e| anyhow::anyhow!("register_setup_responder: {e:?}"))?;

    // CDC functional descriptors (Header, Call Management, ACM, Union) on the
    // control interface, pointing at the data interface registered next.
    let control_func_descriptor: [u8; 19] = [
        0x05, 0x24, 0x00, 0x10, 0x01, // Header
        0x05, 0x24, 0x01, 0x00, interface_num as u8 + 1, // Call Management -> data iface
        0x04, 0x24, 0x02, 0x00, // Abstract Control Management
        0x05, 0x24, 0x06, interface_num as u8, interface_num as u8 + 1, // Union
    ];

    let [_ep_ctrl] = usb_api
        .register_interface(
            IFCE_CDC_CLASS,
            IFCE_CDC_SUBCLASS,
            0x00,
            &CTRL_ENDPOINTS,
            &control_func_descriptor,
            2,
        )
        .map_err(|e| anyhow::anyhow!("register control iface: {e:?}"))?;

    let [ep_out, mut ep_in] = usb_api
        .register_interface(IFCE_CDC_DATA_CLASS, 0x00, 0x00, &DATA_ENDPOINTS, &[], 0)
        .map_err(|e| anyhow::anyhow!("register data iface: {e:?}"))?;

    // These interfaces were added AFTER the device first enumerated (the app starts
    // long after boot), and register_interface does not itself re-enumerate. Force a
    // detach/reattach so the host re-reads the config and binds our CDC port. This is
    // the same mechanism FIDO + mass-storage emulation use for runtime interfaces.
    usb_api.reset_controller();

    log::info!("nunchuk-signer CDC endpoints registered, re-enumerated");

    let (payload_tx, payload_rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || reader_loop(ep_out, payload_tx));

    // Dispatcher + writer fused on one thread (mpsc unpark on Xous is unreliable).
    let usb_api_w = UsbDeviceEmulation::default();
    let mut write_buf = xous::map_memory(None, None, 0x1000, xous::MemoryFlags::W)
        .map_err(|e| anyhow::anyhow!("cdc map write buf: {e:?}"))?;

    while let Ok(payload) = payload_rx.recv() {
        let mut bytes = dispatch(&state, &payload).to_line();
        bytes.push(b'\n');
        for chunk in bytes.chunks(0x1000) {
            write_buf.as_slice_mut::<u8>()[..chunk.len()].copy_from_slice(chunk);
            match ep_in.write_buf(write_buf, chunk.len()) {
                Ok(_) => {}
                Err(usb::error::UsbError::HostDisconnected) => {
                    let _ = usb_api_w.wait_for_connection();
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => log::warn!("cdc write_buf: {e:?}"),
            }
        }
    }
    Ok(())
}

fn reader_loop(mut ep_out: UsbEmulatedEndpoint, payload_tx: mpsc::Sender<Vec<u8>>) {
    let usb_api = UsbDeviceEmulation::default();
    let read_buf = match xous::map_memory(None, None, 0x1000, xous::MemoryFlags::W) {
        Ok(b) => b,
        Err(e) => {
            log::error!("cdc reader: map read buf: {e:?}");
            return;
        }
    };
    let mut line = Vec::<u8>::new();
    loop {
        let got = match ep_out.read_buf(read_buf, 512) {
            Ok(n) => n,
            Err(usb::error::UsbError::HostDisconnected) => {
                line.clear();
                let _ = usb_api.wait_for_connection();
                continue;
            }
            Err(e) => {
                log::warn!("cdc read_buf: {e:?}");
                continue;
            }
        };
        if got == 0 {
            continue;
        }
        let chunk = &read_buf.as_slice::<u8>()[..got];
        for &b in chunk {
            if b == b'\n' {
                if line.is_empty() {
                    continue;
                }
                let payload = std::mem::take(&mut line);
                if payload_tx.send(payload).is_err() {
                    return;
                }
            } else if b != b'\r' {
                line.push(b);
            }
        }
    }
}
