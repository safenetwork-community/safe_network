// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Core;
use crate::dbs::convert_to_error_message as convert_db_error_to_error_message;
use crate::messaging::data::ServiceMsg;
use crate::messaging::NodeAuth;
use crate::messaging::{
    data::{ChunkRead, CmdError, DataCmd, DataQuery, QueryResponse, RegisterRead, RegisterWrite},
    node::{NodeCmd, NodeMsg, NodeQueryResponse},
    AuthorityProof, DstLocation, EndUser, MessageId, MsgKind, ServiceAuth, WireMsg,
};
use crate::routing::core::capacity::CHUNK_COPY_COUNT;
use crate::routing::peer::PeerUtils;
use crate::routing::{error::Result, routing_api::command::Command, section::SectionUtils};
use crate::types::PublicKey;
use itertools::Itertools;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use xor_name::XorName;

impl Core {
    /// Forms a command to send the provided node error out
    pub(crate) fn send_cmd_error_response(
        &self,
        error: CmdError,
        target: EndUser,
        msg_id: MessageId,
    ) -> Result<Vec<Command>> {
        let the_error_msg = ServiceMsg::CmdError {
            error,
            correlation_id: msg_id,
        };

        let dst = DstLocation::EndUser(target);

        // FIXME: define which signature/authority this message should really carry,
        // perhaps it needs to carry Node signature on a NodeMsg::QueryResponse msg type.
        // Giving a random sig temporarily
        let (msg_kind, payload) = Self::random_client_signature(&the_error_msg)?;
        let wire_msg = WireMsg::new_msg(MessageId::new(), payload, msg_kind, dst)?;

        let command = Command::ParseAndSendWireMsg(wire_msg);

        Ok(vec![command])
    }

    /// Handle regsiter commands
    pub(crate) async fn handle_register_write(
        &self,
        msg_id: MessageId,
        register_write: RegisterWrite,
        user: EndUser,
        auth: AuthorityProof<ServiceAuth>,
    ) -> Result<Vec<Command>> {
        match self.register_storage.write(register_write, auth).await {
            Ok(_) => Ok(vec![]),
            Err(error) => {
                trace!("Problem on writing Register! {:?}", error);
                let error = convert_db_error_to_error_message(error);

                let error = CmdError::Data(error);
                self.send_cmd_error_response(error, user, msg_id)
            }
        }
    }

    /// Handle register reads
    pub(crate) fn handle_register_read(
        &self,
        msg_id: MessageId,
        query: RegisterRead,
        user: EndUser,
        auth: AuthorityProof<ServiceAuth>,
    ) -> Result<Vec<Command>> {
        match self.register_storage.read(&query, auth.public_key) {
            Ok(response) => {
                if response.failed_with_data_not_found() {
                    // we don't return data not found errors.
                    return Ok(vec![]);
                }

                let msg = ServiceMsg::QueryResponse {
                    response,
                    correlation_id: msg_id,
                };

                // FIXME: define which signature/authority this message should really carry,
                // perhaps it needs to carry Node signature on a NodeMsg::QueryResponse msg type.
                // Giving a random sig temporarily
                let (msg_kind, payload) = Self::random_client_signature(&msg)?;

                let dst = DstLocation::EndUser(user);
                let wire_msg = WireMsg::new_msg(msg_id, payload, msg_kind, dst)?;

                let command = Command::ParseAndSendWireMsg(wire_msg);

                Ok(vec![command])
            }
            Err(error) => {
                trace!("Problem on reading Register! {:?}", error);
                let error = convert_db_error_to_error_message(error);
                let error = CmdError::Data(error);

                self.send_cmd_error_response(error, user, msg_id)
            }
        }
    }

    /// Sign and serialize node message to be sent
    pub(crate) fn prepare_node_msg(&self, msg: NodeMsg, dst: DstLocation) -> Result<Vec<Command>> {
        let msg_id = MessageId::new();

        let section_pk = *self.section().chain().last_key();

        let payload = WireMsg::serialize_msg_payload(&msg)?;

        let auth = NodeAuth::authorize(section_pk, &self.node().keypair, &payload);
        let msg_kind = MsgKind::NodeAuthMsg(auth.into_inner());

        let wire_msg = WireMsg::new_msg(msg_id, payload, msg_kind, dst)?;

        let command = Command::ParseAndSendWireMsg(wire_msg);

        Ok(vec![command])
    }

    /// Handle chunk read
    pub(crate) async fn handle_chunk_query_at_adult(
        &self,
        msg_id: MessageId,
        query: ChunkRead,
        requester: PublicKey,
        user: EndUser,
    ) -> Result<Vec<Command>> {
        trace!("Handling chunk read at adult");
        let mut commands = vec![];
        if self.chunk_storage.is_storage_getting_full().await {
            let section_pk = self.public_key_set()?.public_key();
            let node_id = self.node().keypair.public;

            let node_xorname = XorName::from(PublicKey::from(node_id));

            // we should notify the section about this
            let msg = NodeMsg::NodeCmd(NodeCmd::StorageFull {
                section: node_xorname,
                node_id: PublicKey::from(self.node().keypair.public),
            });

            let dst = DstLocation::Section {
                name: node_xorname,
                section_pk,
            };

            commands.push(Command::PrepareNodeMsgToSend { msg, dst });
        }

        match self.chunk_storage.read(&query, requester) {
            Ok(response) => {
                let msg = NodeMsg::NodeQueryResponse {
                    response,
                    correlation_id: msg_id,
                    user,
                };

                // Setup node authority on this response and send this back to our elders
                let section_pk = *self.section().chain().last_key();
                let dst = DstLocation::Section {
                    name: query.dst_name(),
                    section_pk,
                };

                commands.push(Command::PrepareNodeMsgToSend { msg, dst });

                Ok(commands)
            }
            Err(error) => {
                error!("Problem reading chunk from storage! {:?}", error);
                // Nothing more to do, we've had a bad time here...
                Ok(commands)
            }
        }
    }

    /// Handle chunk read
    /// Records response in liveness tracking
    /// Forms a response to send to the requester
    pub(crate) async fn handle_chunk_query_response_at_elder(
        &self,
        // msg_id: MessageId,
        correlation_id: MessageId,
        response: NodeQueryResponse,
        user: EndUser,
        sending_nodes_pk: PublicKey,
    ) -> Result<Vec<Command>> {
        let msg_id = MessageId::new();
        let mut commands = vec![];
        debug!(
            "Handling chunk read @ elders, received from {:?} ",
            sending_nodes_pk
        );

        let NodeQueryResponse::GetChunk(response) = response;

        let query_response = QueryResponse::GetChunk(response);

        match query_response.operation_id() {
            Ok(op_id) => {
                let node_id = XorName::from(sending_nodes_pk);
                self.liveness
                    .request_operation_fulfilled(&node_id, op_id)
                    .await
            }
            Err(error) => {
                warn!("Node problems noted when retrieving data: {:?}", error)
            }
        }

        // Check for unresponsive adults here.
        for (name, count) in self.liveness.find_unresponsive_nodes().await {
            warn!(
                "Node {} has {} pending ops. It might be unresponsive",
                name, count
            );
            commands.push(Command::ProposeOffline(name));
        }

        // Send response if one is warrented
        if query_response.failed_with_data_not_found()
            || (!query_response.is_success()
                && self.capacity.is_full(XorName::from(sending_nodes_pk)).await)
        {
            // we don't return data not found errors.
            trace!("Node {:?}, reported data not found", sending_nodes_pk);

            return Ok(commands);
        }

        let msg = ServiceMsg::QueryResponse {
            response: query_response,
            correlation_id,
        };

        // FIXME: define which signature/authority this message should really carry,
        // perhaps it needs to carry Node signature on a NodeMsg::QueryResponse msg type.
        // Giving a random sig temporarily
        let (msg_kind, payload) = Self::random_client_signature(&msg)?;

        let dst = DstLocation::EndUser(user);
        let wire_msg = WireMsg::new_msg(msg_id, payload, msg_kind, dst)?;

        let command = Command::ParseAndSendWireMsg(wire_msg);
        commands.push(command);
        Ok(commands)
    }

    /// Handle ServiceMsgs received from EndUser
    pub(crate) async fn handle_service_msg_received(
        &self,
        msg_id: MessageId,
        msg: ServiceMsg,
        user: EndUser,
        auth: AuthorityProof<ServiceAuth>,
    ) -> Result<Vec<Command>> {
        match msg {
            // Register
            // Commands to be handled at elder.
            ServiceMsg::Cmd(DataCmd::Register(register_write)) => {
                self.handle_register_write(msg_id, register_write, user, auth)
                    .await
            }
            ServiceMsg::Query(DataQuery::Register(read)) => {
                self.handle_register_read(msg_id, read, user, auth)
            }
            // These will only be received at elders.
            // These reads/writes are for adult nodes...
            ServiceMsg::Cmd(DataCmd::Chunk(chunk_write)) => {
                self.write_chunk_to_adults(chunk_write, msg_id, auth, user)
                    .await
            }
            ServiceMsg::Query(DataQuery::Chunk(read)) => {
                self.read_chunk_from_adults(&read, msg_id, auth, user).await
            }

            _ => {
                warn!("!!!! Unexpected ServiceMsg received in routing. Was not sent to node layer: {:?}", msg);
                Ok(vec![])
            }
        }
    }

    // Used to fetch the list of holders for a given chunk.
    pub(crate) async fn get_chunk_holder_adults(&self, target: &XorName) -> BTreeSet<XorName> {
        let full_adults = self.full_adults().await;
        // TODO: reuse our_adults_sorted_by_distance_to API when core is merged into upper layer
        let adults = self
            .section()
            .adults()
            .copied()
            .map(|p2p_node| *p2p_node.name());

        adults
            .sorted_by(|lhs, rhs| target.cmp_distance(lhs, rhs))
            .filter(|name| !full_adults.contains(name))
            .take(CHUNK_COPY_COUNT)
            .collect::<BTreeSet<_>>()
    }

    /// Handle incoming data msgs.
    // TODO: streamline this as full AE for direct messaging.
    pub(crate) async fn handle_service_message(
        &self,
        sender: SocketAddr,
        msg_id: MessageId,
        auth: AuthorityProof<ServiceAuth>,
        msg: ServiceMsg,
        dst_location: DstLocation,
    ) -> Result<Vec<Command>> {
        trace!("Service msg received being handled: {:?}", msg);
        // TODO:
        // Currently clients perform AE msg exchange using `SectionInfoMsg`, that
        // msg type shall be gone in favour of AE-Retry/Redirect responses which
        // shall be sent by the AE checks logic earlier on in the main msg handling flow.

        if let DstLocation::EndUser(_) = dst_location {
            warn!(
                "Service msg has been dropped as its destination location ({:?}) is invalid: {:?}",
                dst_location, msg
            );
            return Ok(vec![]);
        }

        let user = match self.comm.get_connection_id(&sender).await {
            Some(name) => EndUser(name),
            None => {
                error!(
                    "Service msg has been dropped since client connection id for {} was not found: {:?}",
                    sender, msg
                );
                return Ok(vec![]);
            }
        };

        self.handle_service_msg_received(msg_id, msg, user, auth)
            .await
    }
}