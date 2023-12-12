## Dolwnload SRS files

```
sh scripts/download_setup.sh
```

## Build zkspv Prover Docker Image

```
DOCKER_BUILDKIT=0 docker-compose build --no-cache
```

Tips about nvidia-container-runtime: https://stackoverflow.com/questions/59691207/docker-build-with-nvidia-runtime/61737404#61737404


## Start The Prover Service

```
docker-compose up -d
```

Services provide two parameters:

- `cache_srs_pk`: Enabling this parameter allows the service to cache the required srs and pk files on the heap during its initial run. This reduces the unnecessary time spent on reading srs, generating or reading pk files from the hard disk in subsequent proof tasks.
- `generate_smart_contract`:Enabling this parameter allows the generation of an EVM verification contract while generating the proof.