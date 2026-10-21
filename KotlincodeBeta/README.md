# Kotlin proxy

Single-file Kotlin implementation of the SocksHttpGate proxy.

## Requirements

- Kotlin compiler (`kotlinc`).
- JDK 21 or newer is recommended for virtual-thread support; runtime behavior depends on the JDK.

## Run

Use the Kotlin script runner if available:

```sh
kotlin proxy.kt --help
kotlin proxy.kt -l 127.0.0.1 -p 1080 --dashboard-bind 127.0.0.1 --dashboard-port 8081
```

Or compile to a runnable JAR:

```sh
kotlinc proxy.kt -include-runtime -d sockshttpgate-proxy.jar
java -jar sockshttpgate-proxy.jar --help
java -jar sockshttpgate-proxy.jar -l 127.0.0.1 -p 1080 --dashboard-bind 127.0.0.1 --dashboard-port 8081
```

The source documents default proxy port `1080` and dashboard port `8081`. Use `--help` for the authoritative option list.

## Test

```sh
kotlinc proxy.kt -include-runtime -d /tmp/sockshttpgate-proxy.jar
java -jar /tmp/sockshttpgate-proxy.jar --help
```

No dedicated automated test suite is defined in this folder. Validate protocol behavior with local clients and controlled targets.

## Security

Use localhost binding for development. Do not expose the proxy or dashboard publicly without reviewing authentication and access controls. Protect configuration and runtime data files.
