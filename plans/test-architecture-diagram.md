# Test Architecture Overview

```mermaid
graph TB
    subgraph BDD Tests
        BDD1[rsa.feature]
        BDD2[ecdsa.feature]
        BDD3[ed25519.feature]
        BDD4[hmac.feature]
        BDD5[jwk.feature]
        BDD6[jwks.feature]
        BDD7[negative.feature]
        BDD8[seed.feature]
        BDD9[tempfile.feature]
        BDD10[x509.feature]
        BDD11[chain.feature]
        BDD12[cross_key.feature]
    end

    subgraph Proposed BDD Tests
        PBDD1[jwt.feature - NEW]
        PBDD2[tls.feature - NEW]
        PBDD3[edge_cases.feature - NEW]
    end

    subgraph Unit Tests
        UT1[uselesskey-core]
        UT2[uselesskey-rsa]
        UT3[uselesskey-ecdsa]
        UT4[uselesskey-ed25519]
        UT5[uselesskey-x509 - MISSING]
        UT6[uselesskey-hmac - MISSING]
        UT7[uselesskey-jwk - MISSING]
    end

    subgraph Adapter Tests - MISSING
        AT1[uselesskey-jsonwebtoken]
        AT2[uselesskey-rustls]
        AT3[uselesskey-ring]
        AT4[uselesskey-aws-lc-rs]
        AT5[uselesskey-rustcrypto]
    end

    subgraph Integration Tests - MISSING
        IT1[JWT End-to-End]
        IT2[TLS Handshake]
        IT3[mTLS Scenarios]
        IT4[Key Rotation]
    end

    subgraph Property Tests
        PT1[core_prop.rs]
        PT2[rsa_prop.rs]
        PT3[negative_prop.rs]
    end

    subgraph Fuzz Tests
        FT1[der_ops.rs]
        FT2[pem_corrupt.rs]
        FT3[rsa_pkcs8_pem_parse.rs]
    end

    BDD1 --> UT1
    BDD2 --> UT3
    BDD3 --> UT4
    BDD4 --> UT6
    BDD5 --> UT7
    BDD6 --> UT7
    BDD7 --> UT1
    BDD8 --> UT1
    BDD9 --> UT1
    BDD10 --> UT5
    BDD11 --> UT5
    BDD12 --> UT1

    PBDD1 --> AT1
    PBDD2 --> AT2
    PBDD3 --> UT1

    UT1 --> PT1
    UT2 --> PT2
    UT1 --> PT3

    UT1 --> FT1
    UT1 --> FT2
    UT2 --> FT3

    IT1 --> AT1
    IT2 --> AT2
    IT3 --> AT2
    IT4 --> UT7

    style BDD1 fill:#90EE90
    style BDD2 fill:#90EE90
    style BDD3 fill:#90EE90
    style BDD4 fill:#90EE90
    style BDD5 fill:#90EE90
    style BDD6 fill:#90EE90
    style BDD7 fill:#90EE90
    style BDD8 fill:#90EE90
    style BDD9 fill:#90EE90
    style BDD10 fill:#90EE90
    style BDD11 fill:#90EE90
    style BDD12 fill:#90EE90

    style PBDD1 fill:#FFD700
    style PBDD2 fill:#FFD700
    style PBDD3 fill:#FFD700

    style UT5 fill:#FF6B6B
    style UT6 fill:#FF6B6B
    style UT7 fill:#FF6B6B

    style AT1 fill:#FF6B6B
    style AT2 fill:#FF6B6B
    style AT3 fill:#FF6B6B
    style AT4 fill:#FF6B6B
    style AT5 fill:#FF6B6B

    style IT1 fill:#FF6B6B
    style IT2 fill:#FF6B6B
    style IT3 fill:#FF6B6B
    style IT4 fill:#FF6B6B
```

## Test Coverage Matrix

```mermaid
graph LR
    subgraph Key Types
        K1[RSA]
        K2[ECDSA]
        K3[Ed25519]
        K4[HMAC]
        K5[X.509]
    end

    subgraph Test Types
        T1[BDD]
        T2[Unit]
        T3[Property]
        T4[Integration]
    end

    subgraph Coverage Status
        C1[Complete]
        C2[Partial]
        C3[Missing]
    end

    K1 --> T1
    K1 --> T2
    K1 --> T3

    K2 --> T1
    K2 --> T2
    K2 --> T3

    K3 --> T1
    K3 --> T2
    K3 --> T3

    K4 --> T1
    K4 --> C3

    K5 --> T1
    K5 --> C3

    T1 --> C1
    T2 --> C2
    T3 --> C2
    T4 --> C3
```

## Test Execution Flow

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant XTask as cargo xtask
    participant BDD as Cucumber BDD
    participant Unit as cargo test
    participant Prop as proptest
    participant Fuzz as cargo fuzz

    Dev->>XTask: cargo xtask ci
    XTask->>BDD: cargo xtask bdd
    BDD->>BDD: Run feature files
    BDD-->>XTask: BDD results
    XTask->>Unit: cargo test
    Unit->>Unit: Run unit tests
    Unit-->>XTask: Unit test results
    XTask->>Prop: Run property tests
    Prop->>Prop: Generate random inputs
    Prop-->>XTask: Property test results
    XTask-->>Dev: CI report

    Note over Dev,Fuzz: Manual execution
    Dev->>Fuzz: cargo xtask fuzz
    Fuzz->>Fuzz: Run fuzz targets
    Fuzz-->>Dev: Fuzz findings
```

## BDD Test Hierarchy

```mermaid
graph TD
    subgraph Core Concepts
        CC1[Factory]
        CC2[Determinism]
        CC3[Caching]
        CC4[Seed Parsing]
    end

    subgraph Key Generation
        KG1[RSA]
        KG2[ECDSA]
        KG3[Ed25519]
        KG4[HMAC]
    end

    subgraph Key Formats
        KF1[PKCS8 PEM]
        KF2[PKCS8 DER]
        KF3[SPKI PEM]
        KF4[SPKI DER]
        KF5[JWK]
        KF6[JWKS]
    end

    subgraph X.509
        X1[Self-Signed Certs]
        X2[Certificate Chains]
        X3[SANs]
        X4[Negative Variants]
    end

    subgraph Negative Fixtures
        NF1[Corrupted PEM]
        NF2[Truncated DER]
        NF3[Mismatched Keys]
        NF4[Expired Certs]
        NF5[Unknown CA]
    end

    subgraph Integration
        I1[JWT Signing]
        I2[JWT Verification]
        I3[TLS Server Config]
        I4[TLS Client Config]
        I5[mTLS]
    end

    CC1 --> KG1
    CC1 --> KG2
    CC1 --> KG3
    CC1 --> KG4

    KG1 --> KF1
    KG1 --> KF2
    KG1 --> KF3
    KG1 --> KF4
    KG1 --> KF5

    KG2 --> KF1
    KG2 --> KF2
    KG2 --> KF3
    KG2 --> KF4
    KG2 --> KF5

    KG3 --> KF1
    KG3 --> KF2
    KG3 --> KF3
    KG3 --> KF4
    KG3 --> KF5

    KG4 --> KF5
    KG4 --> KF6

    KF5 --> X1
    X1 --> X2
    X2 --> X3
    X2 --> X4

    NF1 --> KG1
    NF1 --> KG2
    NF1 --> KG3
    NF1 --> KG4
    NF1 --> X1

    NF2 --> KG1
    NF2 --> KG2
    NF2 --> KG3
    NF2 --> KG4
    NF2 --> X1

    NF3 --> KG1
    NF3 --> KG2
    NF3 --> KG3

    NF4 --> X2
    NF5 --> X2

    KF5 --> I1
    KF6 --> I2
    X2 --> I3
    X2 --> I4
    I3 --> I5
    I4 --> I5
```

## Legend

- **Green boxes**: Existing tests (complete)
- **Yellow boxes**: Proposed new tests
- **Red boxes**: Missing tests
- **Solid lines**: Direct dependencies
- **Dashed lines**: Indirect relationships
