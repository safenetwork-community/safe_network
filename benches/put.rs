// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use anyhow::Result;
use criterion::{criterion_group, criterion_main, Criterion};
use safe_network::client::utils::generate_random_vector;
use safe_network::client::utils::test_utils::read_network_conn_info;
use safe_network::client::{Client, Error, DEFAULT_QUERY_TIMEOUT};
use tokio::runtime::Runtime;

/// This bench requires a network already set up
async fn put_kbs(amount: usize) -> Result<(), Error> {
    let contact_info = read_network_conn_info().unwrap();
    let size = 1024 * amount;
    let data = generate_random_vector(size);
    let client = Client::new(None, None, Some(contact_info), DEFAULT_QUERY_TIMEOUT).await?;
    let address = client.store_public_blob(&data).await?;

    // small wait for write to go on
    // tokio::time::sleep(Duration::from_secs(2)).await;
    // let's make sure the public chunk is stored
    let received_data = client.read_blob(address, None, None).await?;

    assert_eq!(received_data, data);

    Ok(())
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("put-sampling");

    let runtime = Runtime::new().unwrap();
    group.sample_size(10);
    group.bench_function("put 1kb", |b| {
        b.to_async(&runtime).iter(|| async {
            match put_kbs(1).await {
                Ok(_) => {}
                Err(error) => println!("bench failed with {:?}", error),
            }
        });
    });
    group.bench_function("put 1mb", |b| {
        b.to_async(&runtime).iter(|| async {
            match put_kbs(1024).await {
                Ok(_) => {}
                Err(error) => println!("bench failed with {:?}", error),
            }
        });
    });
    group.finish()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);