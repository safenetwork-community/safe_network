// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{CmdError, Error, QueryResponse};
use serde::{Deserialize, Serialize};
use sn_data_types::{Blob, BlobAddress, PublicKey};
use xor_name::XorName;

/// TODO: docs
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize, Debug)]
pub enum BlobRead {
    /// TODO: docs
    Get(BlobAddress),
}

/// TODO: docs
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize, Debug)]
pub enum BlobWrite {
    /// TODO: docs
    New(Blob),
    /// TODO: docs
    DeletePrivate(BlobAddress),
}

impl BlobRead {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> QueryResponse {
        QueryResponse::GetBlob(Err(error))
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use BlobRead::*;
        match self {
            Get(address) => *address.name(),
        }
    }
}

impl BlobWrite {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> CmdError {
        CmdError::Data(error)
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use BlobWrite::*;
        match self {
            New(ref data) => *data.name(),
            DeletePrivate(ref address) => *address.name(),
        }
    }

    /// Returns the owner of the data on a New Blob write.
    pub fn owner(&self) -> Option<PublicKey> {
        match self {
            Self::New(data) => data.owner().cloned(),
            Self::DeletePrivate(_) => None,
        }
    }
}
