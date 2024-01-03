#  zkspv-circuits

> We extend our heartfelt gratitude to the spirit of open-source community, particularly to projects like [halo2-lib](https://github.com/axiom-crypto/halo2-lib/releases/tag/v0.3.0) and [snark-verifier](https://github.com/axiom-crypto/snark-verifier/tree/v0.1.1). Their pioneering work has laid a solid foundation for our project, enabling us to build upon their achievements and contribute to the collective advancement of our field.

The function of this zero-knowledge proof circuit library is to enable us to have untrusted access to historical data on the blockchain and arbitrary computational expressions.

## Build and usage

### Prerequisites

1. system requirements:
   1. 64-core CPU
   2. Minimum 3080 Nvidia GPU(which supports CUDA Toolkit version 12.0 or above).
   3. Minimum 350GB RAM
   4. Minimum 500GB ROM
2. software requirements:
   1. [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads) version 12.0 or newer.
   2. CMake, version 3.24.3 and above. Latest version is recommended.
   3. Solc, version 0.8.19.

### Build systems

1. All circuits in this project rely on a one-time universal trusted setup, also known as the tau power ceremony. This is the same as the ceremony conducted by the Ethereum Foundation in preparation for EIP-4844 (also known as proto-danksharding). Execute the `download_setup` script to download the halo2-compatible trusted setup files.

   ```bash
   sh scripts/download_setup.sh
   ```



2. Please ensure that the Rust version in use is on the nightly version, then execute the `services` script to start the service.

   ```bash
   sh scripts/services.sh
   ```

## Docker

We offer a simple [Docker container](https://github.com/Orbiter-Finance/zkspv-circuits/blob/dep/docs/deploy.md) so you can simply run zkspv-circuits without setting everything up locally.