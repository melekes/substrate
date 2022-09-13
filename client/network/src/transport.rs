// This file is part of Substrate.

// Copyright (C) 2018-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use libp2p::{
	bandwidth,
	core::{
		self,
		either::{EitherOutput, EitherTransport},
		muxing::StreamMuxerBox,
		transport::{Boxed, OptionalTransport},
		upgrade,
	},
	dns, identity, mplex, noise, tcp, webrtc as webrtc_p2p, websocket, Multiaddr, PeerId,
	Transport,
};
use log::debug;
use std::{sync::Arc, time::Duration};

use libp2p::multiaddr::Protocol;
use std::net::SocketAddr;
use webrtc::peer_connection::certificate::RTCCertificate;

pub use self::bandwidth::BandwidthSinks;

// TODO: implement Into<SocketAddr> for Multiaddr and remove this.
fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Option<SocketAddr> {
	let mut iter = addr.iter();
	let proto1 = iter.next()?;
	let proto2 = iter.next()?;
	let proto3 = iter.next()?;

	for proto in iter {
		match proto {
			Protocol::P2p(_) => {}, /* Ignore a `/p2p/...` prefix of possibly outer protocols, */
			Protocol::Certhash(_) => {},
			_ => return None,
		}
	}

	match (proto1, proto2, proto3) {
		(Protocol::Ip4(ip), Protocol::Udp(port), Protocol::WebRTC) =>
			Some(SocketAddr::new(ip.into(), port)),
		(Protocol::Ip6(ip), Protocol::Udp(port), Protocol::WebRTC) =>
			Some(SocketAddr::new(ip.into(), port)),
		_ => None,
	}
}

/// Builds the transport that serves as a common ground for all connections.
///
/// If `memory_only` is true, then only communication within the same process are allowed. Only
/// addresses with the format `/memory/...` are allowed.
///
/// `yamux_window_size` is the maximum size of the Yamux receive windows. `None` to leave the
/// default (256kiB).
///
/// `yamux_maximum_buffer_size` is the maximum allowed size of the Yamux buffer. This should be
/// set either to the maximum of all the maximum allowed sizes of messages frames of all
/// high-level protocols combined, or to some generously high value if you are sure that a maximum
/// size is enforced on all high-level protocols.
///
/// Returns a `BandwidthSinks` object that allows querying the average bandwidth produced by all
/// the connections spawned with this transport.
pub fn build_transport<'a>(
	keypair: identity::Keypair,
	memory_only: bool,
	yamux_window_size: Option<u32>,
	yamux_maximum_buffer_size: usize,
	webrtc_listen_address: Option<Multiaddr>,
) -> (Boxed<(PeerId, StreamMuxerBox)>, Arc<BandwidthSinks>) {
	// Build the base layer of the transport.
	let transport = if !memory_only {
		let tcp_config = tcp::GenTcpConfig::new().nodelay(true);
		let desktop_trans = tcp::TcpTransport::new(tcp_config.clone());
		let desktop_trans = websocket::WsConfig::new(desktop_trans)
			.or_transport(tcp::TcpTransport::new(tcp_config.clone()));
		let dns_init = futures::executor::block_on(dns::DnsConfig::system(desktop_trans));
		EitherTransport::Left(if let Ok(dns) = dns_init {
			EitherTransport::Left(dns)
		} else {
			let desktop_trans = tcp::TcpTransport::new(tcp_config.clone());
			let desktop_trans = websocket::WsConfig::new(desktop_trans)
				.or_transport(tcp::TcpTransport::new(tcp_config));
			EitherTransport::Right(desktop_trans.map_err(dns::DnsErr::Transport))
		})
	} else {
		EitherTransport::Right(OptionalTransport::some(
			libp2p::core::transport::MemoryTransport::default(),
		))
	};

	let (transport, bandwidth) = bandwidth::BandwidthLogging::new(transport);

	let authentication_config =
		{
			// For more information about these two panics, see in "On the Importance of
			// Checking Cryptographic Protocols for Faults" by Dan Boneh, Richard A. DeMillo,
			// and Richard J. Lipton.
			let noise_keypair = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&keypair)
			.expect("can only fail in case of a hardware bug; since this signing is performed only \
				once and at initialization, we're taking the bet that the inconvenience of a very \
				rare panic here is basically zero");

			// Legacy noise configurations for backward compatibility.
			let noise_legacy =
				noise::LegacyConfig { recv_legacy_handshake: true, ..Default::default() };

			let mut xx_config = noise::NoiseConfig::xx(noise_keypair);
			xx_config.set_legacy_config(noise_legacy);
			xx_config.into_authenticated()
		};

	let multiplexing_config = {
		let mut mplex_config = mplex::MplexConfig::new();
		mplex_config.set_max_buffer_behaviour(mplex::MaxBufferBehaviour::Block);
		mplex_config.set_max_buffer_size(usize::MAX);

		let mut yamux_config = libp2p::yamux::YamuxConfig::default();
		// Enable proper flow-control: window updates are only sent when
		// buffered data has been consumed.
		yamux_config.set_window_update_mode(libp2p::yamux::WindowUpdateMode::on_read());
		yamux_config.set_max_buffer_size(yamux_maximum_buffer_size);

		if let Some(yamux_window_size) = yamux_window_size {
			yamux_config.set_receive_window_size(yamux_window_size);
		}

		core::upgrade::SelectUpgrade::new(yamux_config, mplex_config)
	};

	let transport = transport
		.upgrade(upgrade::Version::V1Lazy)
		.authenticate(authentication_config)
		.multiplex(multiplexing_config)
		.timeout(Duration::from_secs(20));

	if let Some(_) = webrtc_listen_address {
		// TODO: make `cert` an argument
		let kp = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key pair");
		let cert = RTCCertificate::from_key_pair(kp).expect("certificate");
		// TODO: transform fingerprint to multibase multihash
		println!("SHA256 fingerprint {:?}", cert.get_fingerprints().unwrap().first().unwrap());
		let webrtc_transport = webrtc_p2p::transport::WebRTCTransport::new(cert, keypair);
		(
			Transport::map(webrtc_transport.or_transport(transport), |t, _| {
				let (peer_id, conn) = match t {
					EitherOutput::First((peer_id, conn)) => (peer_id, EitherOutput::First(conn)),
					EitherOutput::Second((peer_id, conn)) => (peer_id, EitherOutput::Second(conn)),
				};
				(peer_id, StreamMuxerBox::new(conn))
			})
			.boxed(),
			bandwidth,
		)
	} else {
		(transport.boxed(), bandwidth)
	}
}
