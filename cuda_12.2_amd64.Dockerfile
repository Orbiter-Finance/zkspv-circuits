FROM nvidia/cuda:12.2.2-devel-ubuntu20.04 as base

ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH

WORKDIR /usr/src/zkSpv
ENV DEBIAN_FRONTEND noninteractive

# Install required dependencies
RUN echo 'Acquire::http::Timeout "10";' > /etc/apt/apt.conf.d/99timeout && \
    echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99timeout && \
    apt-get clean && \
    apt-get update && apt-get install -y \
    cmake \
    make \
    bash \
    git \
    openssl \
    libssl-dev \
    gcc \
    g++ \
    curl \
    pkg-config \
    software-properties-common \
    jq \
    openssh-server \
    openssh-client \
    wget \
    vim \
    hub \
    unzip

# https://forums.developer.nvidia.com/t/error-apt-get-updating-from-nvidia-cuda11-2-1-base-ubuntu20-04/209836
RUN rm /etc/apt/sources.list.d/cuda.list
# Install dependencies for RocksDB. `liburing` is not available for Ubuntu 20.04,
# so we use a PPA with the backport
RUN add-apt-repository ppa:savoury1/virtualisation && \
    apt-get update && \
    apt-get install -y \
    gnutls-bin \
    build-essential \
    clang \
    lldb\
    lld \
    liburing-dev \
    libclang-dev


RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    libglib2.0-dev \
    libgl1-mesa-dev \
    libxrender1 \
    libgl1-mesa-glx \
    libxext-dev

# Install docker engine
RUN wget -c -O - https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
RUN apt update; apt install -y docker-ce-cli

# Configurate git to fetch submodules correctly (https://stackoverflow.com/questions/38378914/how-to-fix-git-error-rpc-failed-curl-56-gnutls)
RUN git config --global http.postBuffer 1048576000

# Install Rust and required cargo packages
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN wget -c -O - https://sh.rustup.rs | bash -s -- -y
RUN rustup install nightly-2023-08-21
RUN rustup default stable
RUN cargo install --version=0.5.13 sqlx-cli
RUN cargo install cargo-nextest

# Copy compiler  binaries
# Obtain `solc` 0.8.19.
RUN wget -c https://github.com/ethereum/solc-bin/raw/gh-pages/linux-amd64/solc-linux-amd64-v0.8.19%2Bcommit.7dd6d404 \
    && mv solc-linux-amd64-v0.8.19+commit.7dd6d404 /usr/bin/solc \
    && chmod +x /usr/bin/solc

# Setup the environment
ENV ZKSPV_HOME=/usr/src/zkSpv
ENV PATH="${ZKSPV_HOME}/bin:${PATH}"
ENV CI=1
RUN cargo install sccache
ENV RUSTC_WRAPPER=/usr/local/cargo/bin/sccache

FROM base as nvidia-tools

ENV LD_LIBRARY_PATH /usr/local/cuda/lib64:$LD_LIBRARY_PATH

# Install Rust and required cargo packages
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Setup the environment
ENV ZKSPV_HOME=/usr/src/zkSpv
ENV PATH="${ZKSPV_HOME}/bin:${PATH}"
ENV CI=1
ENV RUSTC_WRAPPER=/usr/local/cargo/bin/sccache
ENV DEBIAN_FRONTEND noninteractive

RUN wget -c https://github.com/Kitware/CMake/releases/download/v3.24.3/cmake-3.24.3-linux-x86_64.sh && \
    chmod +x cmake-3.24.3-linux-x86_64.sh && \
    ./cmake-3.24.3-linux-x86_64.sh --skip-license --prefix=/usr/local

COPY . ${ZKSPV_HOME}/

RUN cd ${ZKSPV_HOME}/ && cargo build --release --bin services --verbose --jobs=20

