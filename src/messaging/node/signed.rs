// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bls;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};

/// Signed that a quorum of the section elders has agreed on something.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Signed {
    /// The BLS public key.
    pub public_key: bls::PublicKey,
    /// The BLS signature corresponding to the public key.
    pub signature: bls::Signature,
}

impl Signed {
    /// Verifies this signed against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.public_key.verify(&self.signature, payload)
    }
}

/// Single share of `Signed`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignedShare {
    /// BLS public key set.
    pub public_key_set: bls::PublicKeySet,
    /// Index of the node that created this signed share.
    pub index: usize,
    /// BLS signature share corresponding to the `index`-th public key share of the public key set.
    pub signature_share: bls::SignatureShare,
}

impl SignedShare {
    /// Creates new signed share.
    pub fn new(
        public_key_set: bls::PublicKeySet,
        index: usize,
        secret_key_share: &bls::SecretKeyShare,
        payload: &[u8],
    ) -> Self {
        Self {
            public_key_set,
            index,
            signature_share: secret_key_share.sign(payload),
        }
    }

    /// Verifies this signed share against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.public_key_set
            .public_key_share(self.index)
            .verify(&self.signature_share, payload)
    }
}

impl Debug for SignedShare {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SignedShare {{ public_key: {:?}, index: {}, .. }}",
            self.public_key_set.public_key(),
            self.index
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::SecretKey;

    #[test]
    fn verify_signed() {
        let sk = SecretKey::random();
        let public_key = sk.public_key();
        let data = "hello".to_string();
        let signature = sk.sign(&data);
        let signed = Signed {
            public_key,
            signature,
        };
        assert!(signed.verify(&data.as_bytes()));
    }
}
