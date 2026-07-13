# fuzz

The cargo-fuzz harness lands with the M1 issue "Implement the hardened JOSE
core with fuzzing and algorithm exclusions", as a standalone crate that is
deliberately not a workspace member: its libFuzzer dependency needs a nightly
toolchain and must not constrain the stable workspace (the same pattern the
sibling Iron projects use). The CI fuzz lane is added in that issue together
with the first real fuzz targets and the JOSE CVE regression corpus.
