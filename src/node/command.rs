// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::stage::State;
use crate::{
    consensus::{ProofShare, Vote},
    location::{DstLocation, SrcLocation},
    messages::Message,
};
use bytes::Bytes;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    time::Duration,
};

/// Command for node.
pub(crate) enum Command {
    /// Handle `message` from `sender`.
    /// Note: `sender` is `Some` if the message was received from someone else
    /// and `None` if it came from an accumulated `Vote::SendMessage`
    HandleMessage {
        sender: Option<SocketAddr>,
        message: Message,
    },
    /// Handle a timeout previously scheduled with `ScheduleTimeout`.
    HandleTimeout(u64),
    /// Handle peer that's been detected as lost.
    HandlePeerLost(SocketAddr),
    /// Handle vote cast either by us or some other peer.
    HandleVote { vote: Vote, proof_share: ProofShare },
    /// Send a message to `delivery_group_size` peers out of the given `recipients`.
    SendMessage {
        recipients: Vec<SocketAddr>,
        delivery_group_size: usize,
        message: Bytes,
    },
    /// Send `UserMessage` with the given source and destination.
    SendUserMessage {
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    },
    /// Send `BootstrapRequest` to the given recipients.
    SendBootstrapRequest(Vec<SocketAddr>),
    /// Schedule a timeout after the given duration. When the timeout expires, a `HandleTimeout`
    /// command is pushed into the command queue. The token is used to identify the timeout.
    ScheduleTimeout { duration: Duration, token: u64 },
    /// Transition into the given state.
    Transition(Box<State>),
}

impl Debug for Command {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::HandleMessage { sender, message } => f
                .debug_struct("HandleMessage")
                .field("sender", sender)
                .field("message", message)
                .finish(),
            Self::HandleTimeout(token) => f.debug_tuple("HandleTimeout").field(token).finish(),
            Self::HandlePeerLost(addr) => f.debug_tuple("HandlePeerLost").field(addr).finish(),
            Self::HandleVote { vote, proof_share } => f
                .debug_struct("HandleVote")
                .field("vote", vote)
                .field("index", &proof_share.index)
                .finish(),
            Self::SendMessage {
                recipients,
                delivery_group_size,
                message,
            } => f
                .debug_struct("SendMessage")
                .field("recipients", recipients)
                .field("delivery_group_size", delivery_group_size)
                .field("message", &format_args!("{:10}", hex_fmt::HexFmt(message)))
                .finish(),
            Self::SendUserMessage { src, dst, content } => f
                .debug_struct("SendUserMessage")
                .field("src", src)
                .field("dst", dst)
                .field("content", &format_args!("{:10}", hex_fmt::HexFmt(content)))
                .finish(),
            Self::SendBootstrapRequest(recipients) => f
                .debug_tuple("SendBootstrapRequest")
                .field(recipients)
                .finish(),
            Self::ScheduleTimeout { duration, token } => f
                .debug_struct("ScheduleTimeout")
                .field("duration", duration)
                .field("token", token)
                .finish(),
            Self::Transition(state) => f.debug_tuple("Transition").field(state).finish(),
        }
    }
}
