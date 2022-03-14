use std::collections::{BTreeMap, BTreeSet};

use bls_dkg::{PublicKeySet, SecretKeyShare};
use core::fmt::Debug;
use xor_name::XorName;

use sn_membership::consensus::{Consensus, VoteResponse};
use sn_membership::vote::{Ballot, SignedVote, Vote};
use sn_membership::{Error, NodeId, Result};

use crate::messaging::system::{MembershipState, NodeState};

const SOFT_MAX_MEMBERS: usize = 21;
pub type Generation = u64;

#[derive(Debug, Clone)]
pub struct Membership {
    consensus: Consensus<NodeState>,
    bootstrap_members: BTreeSet<NodeState>,
    gen: Generation,
    history: BTreeMap<Generation, Consensus<NodeState>>,
}

impl Membership {
    pub fn from(
        secret_key: (NodeId, SecretKeyShare),
        elders: PublicKeySet,
        n_elders: usize,
        bootstrap_members: BTreeSet<NodeState>,
    ) -> Self {
        Membership {
            consensus: Consensus::from(secret_key, elders, n_elders),
            bootstrap_members,
            gen: 0,
            history: BTreeMap::default(),
        }
    }

    pub fn consensus_at_gen(&self, gen: Generation) -> Result<&Consensus<NodeState>> {
        if gen == self.gen + 1 {
            Ok(&self.consensus)
        } else {
            self.history.get(&gen).ok_or(Error::BadGeneration {
                requested_gen: gen,
                gen: self.gen,
            })
        }
    }

    pub fn consensus_at_gen_mut(&mut self, gen: Generation) -> Result<&mut Consensus<NodeState>> {
        if gen == self.gen + 1 {
            Ok(&mut self.consensus)
        } else {
            self.history.get_mut(&gen).ok_or(Error::BadGeneration {
                requested_gen: gen,
                gen: self.gen,
            })
        }
    }

    pub fn section_member_states(&self, gen: Generation) -> Result<BTreeMap<XorName, NodeState>> {
        let mut members =
            BTreeMap::from_iter(self.bootstrap_members.iter().cloned().map(|n| (n.name, n)));

        if gen == 0 {
            return Ok(members);
        }

        for (history_gen, consensus) in self.history.iter() {
            let decision = if let Some(decision) = consensus.decision.as_ref() {
                decision
            } else {
                panic!(
                    "historical consensus entry without decision {}: {:?}",
                    history_gen, consensus
                );
            };

            for (node_state, _sig) in decision.proposals.iter() {
                members.insert(node_state.name, node_state.clone());
            }

            if history_gen == &gen {
                return Ok(members);
            }
        }

        Err(Error::InvalidGeneration(gen))
    }

    pub fn propose(&mut self, node_state: NodeState) -> Result<SignedVote<NodeState>> {
        info!("[{}] proposing {:?}", self.id(), node_state);
        let vote = Vote {
            gen: self.gen + 1,
            ballot: Ballot::Propose(node_state),
            faults: self.consensus.faults(),
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_proposals(&signed_vote)?;
        self.consensus
            .detect_byzantine_voters(&signed_vote)
            .map_err(|_| Error::AttemptedFaultyProposal)?;
        self.cast_vote(signed_vote)
    }

    pub fn anti_entropy(&self, from_gen: Generation) -> Result<Vec<SignedVote<NodeState>>> {
        info!("[MBR] anti-entropy from gen {}", from_gen);

        let mut msgs = self
            .history
            .iter() // history is a BTreeSet, .iter() is ordered by generation
            .filter(|(gen, _)| **gen > from_gen)
            .filter_map(|(gen, c)| c.decision.clone().map(|d| (gen, c, d)))
            .map(|(gen, c, decision)| {
                c.build_super_majority_vote(decision.votes, decision.faults, *gen)
            })
            .collect::<Result<Vec<_>>>()?;

        // include the current in-progres votes as well.
        msgs.extend(self.consensus.votes.values().cloned());

        Ok(msgs)
    }

    pub fn id(&self) -> NodeId {
        self.consensus.id()
    }

    pub fn handle_signed_vote(
        &mut self,
        signed_vote: SignedVote<NodeState>,
    ) -> Result<VoteResponse<NodeState>> {
        self.validate_proposals(&signed_vote)?;

        let vote_gen = signed_vote.vote.gen;

        let consensus = self.consensus_at_gen_mut(vote_gen)?;
        let vote_response = consensus.handle_signed_vote(signed_vote)?;

        if consensus.decision.is_some() && vote_gen == self.gen + 1 {
            let next_consensus = Consensus::from(
                self.consensus.secret_key.clone(),
                self.consensus.elders.clone(),
                self.consensus.n_elders,
            );

            let decided_consensus = std::mem::replace(&mut self.consensus, next_consensus);
            self.history.insert(vote_gen, decided_consensus);
            self.gen = vote_gen
        }

        Ok(vote_response)
    }

    pub fn sign_vote(&self, vote: Vote<NodeState>) -> Result<SignedVote<NodeState>> {
        self.consensus.sign_vote(vote)
    }

    pub fn cast_vote(
        &mut self,
        signed_vote: SignedVote<NodeState>,
    ) -> Result<SignedVote<NodeState>> {
        self.consensus.cast_vote(signed_vote)
    }

    pub fn validate_proposals(&self, signed_vote: &SignedVote<NodeState>) -> Result<()> {
        // ensure we have a consensus instance for this votes generations
        let _ = self.consensus_at_gen(signed_vote.vote.gen)?;

        signed_vote
            .proposals()
            .into_iter()
            .try_for_each(|reconfig| self.validate_node_state(reconfig, signed_vote.vote.gen))
    }

    pub fn validate_node_state(&self, node_state: NodeState, gen: Generation) -> Result<()> {
        assert!(gen > 0);
        let members = self.section_member_states(gen - 1)?;
        match node_state.state {
            MembershipState::Joined => {
                if members.contains_key(&node_state.name) {
                    Err(Error::JoinRequestForExistingMember)
                } else if members.len() >= SOFT_MAX_MEMBERS {
                    Err(Error::MembersAtCapacity)
                } else {
                    Ok(())
                }
            }
            MembershipState::Left | MembershipState::Relocated(_) => {
                if let Some(prev_state) = members.get(&node_state.name) {
                    if prev_state.state == MembershipState::Joined {
                        Ok(())
                    } else {
                        Err(Error::LeaveRequestForNonMember) // TODO: change this error response
                    }
                } else {
                    Err(Error::LeaveRequestForNonMember)
                }
            }
        }
    }
}
