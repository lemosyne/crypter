use criterion::{criterion_group, criterion_main, Criterion};
use crypter::{openssl::*, Crypter, StatefulCrypter};
use rand::{rngs::ThreadRng, RngCore};

const BLOCK_SIZE: usize = 4096;
const NUM_BLOCKS: usize = 1024;

fn rand_bytes(rng: &mut impl RngCore, n: usize) -> Vec<u8> {
    let mut bytes = vec![0; n];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Per-Block Encryption/Decryption Throughput");

    // We'll just test encrypting and decrypting 1024 blocks.
    let mut rng = ThreadRng::default();
    let mut data = rand_bytes(&mut rng, NUM_BLOCKS * BLOCK_SIZE);

    // Stateless AES128 in CTR mode.
    group.bench_function("Aes128Ctr", |b| {
        b.iter(|| {
            for i in 0..NUM_BLOCKS {
                let key = rand_bytes(&mut rng, Aes128Ctr::key_length());
                let iv = rand_bytes(&mut rng, Aes128Ctr::iv_length());

                let start = i * BLOCK_SIZE;
                let end = start + BLOCK_SIZE;

                Aes128Ctr::encrypt(&key, &iv, &mut data[start..end]).unwrap();
                Aes128Ctr::decrypt(&key, &iv, &mut data[start..end]).unwrap();
            }
        })
    });

    // Stateless AES256 in CTR mode.
    group.bench_function("Aes256Ctr", |b| {
        b.iter(|| {
            for i in 0..NUM_BLOCKS {
                let key = rand_bytes(&mut rng, Aes256Ctr::key_length());
                let iv = rand_bytes(&mut rng, Aes256Ctr::iv_length());

                let start = i * BLOCK_SIZE;
                let end = start + BLOCK_SIZE;

                Aes256Ctr::encrypt(&key, &iv, &mut data[start..end]).unwrap();
                Aes256Ctr::decrypt(&key, &iv, &mut data[start..end]).unwrap();
            }
        })
    });

    // Stateful AES128 in CTR mode.
    group.bench_function("StatefulAes128Ctr", |b| {
        let mut crypter = StatefulAes128Ctr::new();
        b.iter(|| {
            for i in 0..NUM_BLOCKS {
                let key = rand_bytes(&mut rng, StatefulAes128Ctr::key_length());
                let iv = rand_bytes(&mut rng, StatefulAes128Ctr::iv_length());

                let start = i * BLOCK_SIZE;
                let end = start + BLOCK_SIZE;

                crypter.encrypt(&key, &iv, &mut data[start..end]).unwrap();
                crypter.decrypt(&key, &iv, &mut data[start..end]).unwrap();
            }
        })
    });

    // Stateful AES256 in CTR mode.
    group.bench_function("StatefulAes256Ctr", |b| {
        let mut crypter = StatefulAes256Ctr::new();
        b.iter(|| {
            for i in 0..NUM_BLOCKS {
                let key = rand_bytes(&mut rng, StatefulAes256Ctr::key_length());
                let iv = rand_bytes(&mut rng, StatefulAes256Ctr::iv_length());

                let start = i * BLOCK_SIZE;
                let end = start + BLOCK_SIZE;

                crypter.encrypt(&key, &iv, &mut data[start..end]).unwrap();
                crypter.decrypt(&key, &iv, &mut data[start..end]).unwrap();
            }
        })
    });
    group.finish();
}

criterion_group!(benches, bench);

criterion_main! {
    benches
}
