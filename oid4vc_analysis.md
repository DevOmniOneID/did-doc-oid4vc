# OID4VC 분석서

## 1. 범위 및 목표


## 2. 요구사항 도출
### 2.1 기능 요구사항
### 2.2 비기능 요구사항


## 3. 목표 시스템 구성


## 4. OID4VC 분석 결과
### 4.1 공통 요소 // 아래 세부 목차는 자유롭게 바꾸셔도 됩니다.
#### 4.1.1 JWT / JWS / JWE 구조
#### 4.1.2 JWK Key 전달 및 검증
#### 4.1.3 OAuth 2.0 및 TLS 요구사항
#### 4.1.4 Credential Metadata 구조 (`credential_configurations_supported`)

### 4.2 OID4VCI // 아래 세부 목차는 자유롭게 바꾸셔도 됩니다.
#### 4.2.1 Credential Metadata 조회
#### 4.2.2 Credential Request 구조 (JWE + Proof JWT)
#### 4.2.3 ECDH Key 교환 및 암호화 처리
#### 4.2.4 Access Token 처리 (Bearer 토큰)
#### 4.2.5 발급 예외처리 및 실패 응답 패턴

### 4.3 OID4VP // 아래 세부 목차는 자유롭게 바꾸셔도 됩니다.
#### 4.3.1 Verifier Request Object 처리
#### 4.3.2 DCQL 쿼리 처리 및 VP 구성
#### 4.3.3 Response Mode 유형 및 처리 방식
#### 4.3.4 VP Token 생성 및 서명
#### 4.3.5 제출 흐름별 UX 설계 (Cross / Same Device)

### 4.4 SIOPv2

#### 4.4.1 개요 및 역할

**SIOPv2 (Self-Issued OpenID Provider v2)**는 사용자가 자기 자신을 OpenID Provider로 삼아, **중앙 ID 제공자 없이 스스로 인증을 수행하는 분산 신원 인증 모델**입니다.

- 기존의 Google, Facebook 같은 중앙화된 IDP 구조를 대체
- 사용자가 직접 **ID Token을 생성**하고, 이를 제시함으로써 **자기주권형 신원(Self-Sovereign Identity, SSI)** 실현
- OpenID Connect(OIDC)의 흐름을 그대로 따르므로 기존 생태계와의 호환성 확보

**핵심 포인트:**
- 사용자가 직접 서명한 JWT ID Token을 발급
- DID 기반으로 사용자를 식별 및 검증
- VC 발급 요청(OID4VCI) 또는 VC 제시(OID4VP) 시에 인증 주체로 사용됨

---

#### 4.4.2 OID4VCI에서의 Client Authentication 방식으로 사용

OID4VCI에서 사용자는 Credential Issuer에게 VC 발급을 요청합니다.  
이때 Issuer는 요청자의 신원을 확인해야 하며, **Client Authentication** 방식으로 **SIOP 기반 ID Token**이 활용됩니다.

###### 🔒 흐름 요약:
1. 사용자가 지갑을 통해 VC 발급 요청
2. 지갑은 **SIOP 방식으로 ID Token 생성**
3. Credential Issuer는 해당 ID Token을 검증하여 사용자 식별 및 인증 수행

> ✅ 기존 `client_secret`, `client_assertion` 방식 대신 사용자가 **직접 서명한 ID Token**을 사용하는 방식

---

#### 4.4.3 OID4VP에서의 Subject 인증 방식으로 사용

OID4VP는 사용자가 VC를 제시할 때, Verifier가 **“누가 제시했는가”**를 검증해야 합니다.  
이때 SIOPv2는 **VC의 제시 주체(Subject)** 인증 수단으로 사용됩니다.

##### 🧩 인증 흐름:
1. Verifier가 Presentation Request 전송
2. Wallet이 **SIOPv2 방식의 ID Token** 생성
3. VP와 함께 Verifier에게 전달
4. Verifier는 ID Token의 서명을 확인하고, DID를 통해 소유자 식별

---

#### 4.4.4 ID Token 발급 구조 (JWT + DID)

SIOPv2에서 발급하는 ID Token은 다음과 같은 **JWT 구조**를 가집니다:

##### 📦 JWT 구성:

###### Header
```json
{
  "alg": "ES256K",
  "typ": "JWT",
  "kid": "did:example:123#key-1"
}
```

###### Payload (예시)
```json
{
  "iss": "did:example:123",
  "sub": "did:example:123",
  "aud": "https://verifier.example.org",
  "iat": 1689456000,
  "exp": 1689463200,
  "sub_jwk": {
    "kty": "EC",
    "crv": "secp256k1",
    "x": "...",
    "y": "..."
  }
}
```

###### Signature
- DID Document에 등록된 키로 서명
- 공개키는 DID를 통해 검증 가능

---

#### 4.4.5 SIOP 기반 Wallet의 검증 흐름

지갑이 인증 주체로 동작할 때, Verifier 또는 Credential Issuer는 지갑이 제시하는 **ID Token의 진위**와 **서명자 식별자(DID)**를 검증합니다.

##### ▶️ 시퀀스 다이어그램 (OID4VP 기준)

![SIOP 시퀀스](./siop.svg)

##### 🧠 설명 요약:

1. **Wallet**은 DID를 기반으로 JWT 서명
2. **Verifier**는 해당 DID를 resolve 하여 공개키 확보
3. **JWT의 서명과 Claim 유효성**을 검증하여 사용자의 소유권 확인

---

#### 🔚 정리

| 항목 | 설명 |
|------|------|
| **SIOPv2** | 사용자가 직접 인증 주체가 되는 분산 ID 방식 |
| **OID4VCI** | VC 발급 시 지갑이 ID Token을 이용해 자신을 인증 |
| **OID4VP** | VC 제시 시 지갑이 제시자의 신원을 ID Token으로 증명 |
| **ID Token 구조** | JWT 형식, DID 기반 발급자, 서명 포함 |
| **검증 흐름** | DID → 공개키 → JWT 서명 및 Claim 검증 |

> ✅ **SIOPv2는 Self-Sovereign Identity 실현을 위한 핵심 구성요소로, 신뢰 가능한 자기주권형 인증을 구현합니다.**




## 5. OID4VC 적용 전략


## 6. 부록
