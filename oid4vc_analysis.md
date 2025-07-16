# OID4VC 분석서

- 주제 : OID4VC 분석서
- 작성 : 오픈소스개발팀
- 일자 : 2025-07-18
- 버전 : v1.0.0

| 버전 | 일자       | 변경         |
| ------- | ---------- | --------------- |
| v1.0.0  | 2025-07-18 | 최초 작성 |


## 1. 범위 및 목표

Open DID 플랫폼에 OID4VC 도입을 통해 EUDIW(EU Digital Identity Wallet) 등 다양한 디지털 월렛과의 연동을 목표로 상호운용성을 개선하는 데 중점을 둡니다. 또한 OpenID와 OAuth 2.0 등 국제적으로 검증된 개방형 표준 프로토콜을 기반으로 전체 시스템을 구조화합니다. 이와 함께 기존 Open DID의 레거시 요소를 정비하여 기술부채를 해소하고, 기존 기술요소를 고도화하고 Open DID의 원칙을 더욱 준수하고자 합니다.
- **(상호운용성 개선)** : EUDIW(EU Digital Identity Wallet) 등과의 호환성 확보
- **(개방형 표준 준수)** : OpenID 및 OAuth 2.0 등 개방형 표준 프로토콜 기반 규격화
- **(기술부채 해결)** : Server Token 등 기존 Legacy 고도화
![OID4VC](./goals.png)

## 2. 요구사항 도출
### 2.1 기능 요구사항
### 2.2 비기능 요구사항


## 3. 목표 시스템 구성


## 4. OID4VC 분석 결과
### 4.1 공통 요소 // 아래 세부 목차는 자유롭게 바꾸셔도 됩니다.
### 4.1.1 JWT / JWS / JWE 구조
### 4.1.2 JWK Key 전달 및 검증
### 4.1.3 OAuth 2.0 및 TLS 요구사항
### 4.1.4 Credential Metadata 구조 (`credential_configurations_supported`)


### 4.2 OID4VCI
<br>

### 4.2.1 ODI4VCI 개요
#### 4.2.1.1 OAuth 2.0 적용 범위

OID4VCI는 VC 발급 과정을 OAuth 2.0의 흐름에 맞춰 모델링합니다.
- **Wallet**: OAuth 2.0의 `Client` 역할을 수행합니다.
- **사용자 (End-User)**: `Resource Owner`로서 자신의 데이터에 대한 접근 권한을 Wallet에 부여합니다.
- **Credential Issuer**: VC를 발급하는 주체로, `Resource Server`의 역할을 합니다.
- **Authorization Server**: 사용자의 인증 및 동의를 처리하고 접근 토큰을 발급하는 `Authorization Server`입니다. Credential Issuer가 이 역할을 겸할 수 있습니다.

#### 4.2.1.2 Authorization Code Flow vs. Pre-Authorized Code Flow

OID4VCI는 두 가지 주요 발급 흐름을 지원하여 다양한 시나리오에 대응합니다.

- **Authorization Code Flow**: 사용자의 명시적인 인증과 동의가 필요한 전통적인 웹 기반 흐름입니다. Wallet은 사용자를 Authorization Server로 리디렉션하여 로그인 및 동의 절차를 거친 후, 발급에 필요한 토큰을 받습니다.

![Authorization Code Flow](./oid4vci_authorization_code_flow.svg)

- **Pre-Authorized Code Flow**: 사용자가 이미 다른 채널(예: 이메일, SMS, 오프라인)을 통해 인증 및 동의를 완료했다고 가정하는 흐름입니다. Wallet은 `Credential Offer`에 포함된 `pre-authorized_code`를 사용하여 즉시 토큰을 발급받으며, 사용자 리디렉션 과정이 생략되어 UX가 간소화됩니다.

![Pre-Authorized Code Flow](./oid4vci_pre_authorized_code_flow.svg)
---

- 
<br>

### 4.2.2 OID4VCI Endpoint


**단계 1: Credential Offer (자격증명 제공)**

- 프로토콜의 시작점으로, 발급자가 Wallet에게 발급 가능한 VC와 발급 절차를 시작하는 데 필요한 정보를 전달하는 과정입니다. 이 정보는 `Credential Offer` 객체에 담겨 있으며, URI를 통해 값으로 전달되거나(pass-by-value) 해당 URI에서 직접 GET 요청으로 가져올 수 있습니다(pass-by-reference).

*   **`credential_offer` 객체 주요 파라미터:**
    *   `credential_issuer` (필수): 발급자의 고유 식별자 URL. 이 URL은 발급자 메타데이터를 찾는 데 사용됩니다.
    *   `credentials` (필수): 발급자가 제공하는 VC의 종류를 명시하는 배열. 각 항목은 `format` (예: `jwt_vc_json`), `types` 등 VC의 구체적인 속성을 포함합니다.
    *   `grants` (조건부 필수): VC 발급을 위해 지원되는 OAuth 2.0 인가 그랜트(Grant) 정보를 담는 객체. `authorization_code` 또는 `urn:ietf:params:oauth:grant-type:pre-authorized_code` 중 하나 이상이 반드시 포함되어야 합니다.

---

**단계 2: Issuer Metadata 조회 (발급자 메타데이터 조회)**

- Wallet은 `Credential Offer`에서 얻은 `credential_issuer` URL을 사용하여, `/.well-known/openid-credential-issuer` 경로로 GET 요청을 보내 발급자의 메타데이터를 획득합니다. 이 메타데이터는 VC 발급에 필요한 모든 엔드포인트 URL, 지원 기능, VC 상세 정보 등을 담고 있어 동적인 설정이 가능하게 합니다. (상세 내용은 `4.2.3` 참조)

---

**단계 3: Authorization Grant & Token Acquisition (인가 및 토큰 획득)**

- Wallet은 발급자 메타데이터에 명시된 `grants` 정보를 바탕으로 VC 발급에 필요한 접근 토큰(Access Token)을 획득합니다.

1.  **Authorization Code Grant (사용자 승인 필요):**
    *   **인가 요청:** Wallet은 발급받을 VC의 `id`나 `types`를 `scope` 파라미터에 포함하여, 메타데이터에 명시된 `authorization_endpoint`로 사용자를 리디렉션합니다.
    *   **사용자 인증/동의:** 사용자는 인가 서버에서 인증(로그인)하고, Wallet이 요청한 VC 발급에 대한 동의를 수행합니다.
    *   **토큰 요청:** 인가 서버가 `redirect_uri`로 `인가 코드(code)`를 반환하면, Wallet은 이 코드를 `token_endpoint`에 보내 `Access Token`, `Refresh Token`(선택), 그리고 `c_nonce`(Credential Nonce)를 발급받습니다. `c_nonce`는 이후 VC 요청과 토큰을 암호학적으로 바인딩하는 데 사용됩니다.

2.  **Pre-Authorized Code Grant (사전 승인):**
    *   **개념:** 사용자가 이미 다른 채널을 통해 인증 및 동의를 완료했음을 전제로, `Credential Offer`에 포함된 `pre-authorized_code`를 사용하여 즉시 토큰을 발급받는 방식입니다.
    *   **토큰 요청:** Wallet은 `pre-authorized_code`를 `token_endpoint`에 직접 제출하여 `Access Token`과 `c_nonce`를 획득합니다. 이 흐름에서는 사용자 리디렉션이 발생하지 않습니다.
    *   `tx_code` (Transaction Code): 선택적으로 사용자 확인을 위해 간단한 추가 인증(예: PIN)을 요구할 수 있으며, 이 정보는 `Credential Offer`의 `tx_code` 필드에 명시됩니다.

---

**단계 4: Credential Request (자격증명 요청)**

- Wallet은 획득한 `Access Token`을 사용하여 발급자의 `credential_endpoint`에 VC 발급을 공식적으로 요청합니다. 이 요청은 `POST` 메서드를 사용하며, `Authorization: Bearer <Access Token>` 헤더를 포함해야 합니다.

*   **요청 본문(Request Body) 주요 파라미터:**
    *   `format` (필수): 발급받을 VC의 포맷 (예: `jwt_vc_json`). 메타데이터의 `credentials_supported`에 명시된 값이어야 합니다.
    *   `types` (선택): 발급받을 VC의 `types`.
    *   `proof` (조건부 필수): Holder(소유자)가 VC에 포함될 `credentialSubject`의 제어권을 가지고 있음을 증명하는 암호학적 증명입니다. 이는 VC가 올바른 주체에게 발급되도록 보장하는 핵심 보안 요소입니다.
        *   **`proof_type`**: `jwt` 또는 `ldp_vp` 등 증명 유형.
        *   **`jwt`**: Holder의 개인키로 서명된 JWT. 이 JWT의 Payload에는 `iss` (Holder의 DID), `aud` (발급자 `credential_issuer` URL), 그리고 토큰 응답에서 받은 `c_nonce`가 포함되어야 합니다. 발급자는 이 서명과 `c_nonce`를 검증하여 요청의 유효성을 확인합니다.

---

**단계 5: Credential Response (자격증명 응답)**

- 발급자는 요청을 모두 검증한 후, VC를 생성하여 Wallet에 반환합니다.

*   **성공 응답 (Success):**
    *   `format` (필수): 발급된 VC의 포맷.
    *   `credential` (필수): 발급된 VC. `jwt_vc_json` 형식의 경우 JWS로 표현됩니다.
    *   `c_nonce`, `c_nonce_expires_in` (선택): 새로운 `c_nonce`를 발급하여, 동일한 `Access Token`으로 여러 VC를 순차적으로 발급받을 수 있도록 합니다.

*   **지연된 발급 (Deferred Issuance):**
    *   VC 생성에 시간이 걸리는 경우, 발급자는 `202 Accepted` 상태 코드와 함께 `acceptance_token`을 반환합니다.
    *   Wallet은 이 `acceptance_token`을 사용하여 나중에 메타데이터에 명시된 `deferred_credential_endpoint`로 VC를 조회할 수 있습니다.

*   **오류 응답 (Error):**
    *   `invalid_token`, `unsupported_credential_type` 등 OAuth 2.0 표준에 정의된 오류 코드를 사용하여 실패 이유를 명확히 전달합니다.

---

<br>

### 4.2.3 OID4VCI Issue Metadata

<br>

### 4.3 OID4VP // 아래 세부 목차는 자유롭게 바꾸셔도 됩니다.
### 4.3.1 Verifier Request Object 처리
### 4.3.2 DCQL 쿼리 처리 및 VP 구성
### 4.3.3 Response Mode 유형 및 처리 방식
### 4.3.4 VP Token 생성 및 서명
### 4.3.5 제출 흐름별 UX 설계 (Cross / Same Device)

### 4.4 SIOPv2

### 4.4.1 개요 및 역할

**SIOPv2 (Self-Issued OpenID Provider v2)**는 사용자가 자기 자신을 OpenID Provider로 삼아, **중앙 ID 제공자 없이 스스로 인증을 수행하는 분산 신원 인증 모델**입니다.

- 기존의 Google, Facebook 같은 중앙화된 IDP 구조를 대체
- 사용자가 직접 **ID Token을 생성**하고, 이를 제시함으로써 **자기주권형 신원(Self-Sovereign Identity, SSI)** 실현
- OpenID Connect(OIDC)의 흐름을 그대로 따르므로 기존 생태계와의 호환성 확보

**핵심 포인트:**
- 사용자가 직접 서명한 JWT ID Token을 발급
- DID 기반으로 사용자를 식별 및 검증
- VC 발급 요청(OID4VCI) 또는 VC 제시(OID4VP) 시에 인증 주체로 사용됨

---

### 4.4.2 OID4VCI에서의 Client Authentication 방식으로 사용

OID4VCI에서 사용자는 Credential Issuer에게 VC 발급을 요청합니다.  
이때 Issuer는 요청자의 신원을 확인해야 하며, **Client Authentication** 방식으로 **SIOP 기반 ID Token**이 활용됩니다.

##### 🔒 흐름 요약:
1. 사용자가 지갑을 통해 VC 발급 요청
2. 지갑은 **SIOP 방식으로 ID Token 생성**
3. Credential Issuer는 해당 ID Token을 검증하여 사용자 식별 및 인증 수행

> ✅ 기존 `client_secret`, `client_assertion` 방식 대신 사용자가 **직접 서명한 ID Token**을 사용하는 방식

---

### 4.4.3 OID4VP에서의 Subject 인증 방식으로 사용

OID4VP는 사용자가 VC를 제시할 때, Verifier가 **“누가 제시했는가”**를 검증해야 합니다.  
이때 SIOPv2는 **VC의 제시 주체(Subject)** 인증 수단으로 사용됩니다.

#### 🧩 인증 흐름:
1. Verifier가 Presentation Request 전송
2. Wallet이 **SIOPv2 방식의 ID Token** 생성
3. VP와 함께 Verifier에게 전달
4. Verifier는 ID Token의 서명을 확인하고, DID를 통해 소유자 식별

---

### 4.4.4 ID Token 발급 구조 (JWT + DID)

SIOPv2에서 발급하는 ID Token은 다음과 같은 **JWT 구조**를 가집니다:

#### 📦 JWT 구성:

##### Header
```json
{
  "alg": "ES256K",
  "typ": "JWT",
  "kid": "did:example:123#key-1"
}
```

##### Payload (예시)
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

##### Signature
- DID Document에 등록된 키로 서명
- 공개키는 DID를 통해 검증 가능

---

### 4.4.5 SIOP 기반 Wallet의 검증 흐름

지갑이 인증 주체로 동작할 때, Verifier 또는 Credential Issuer는 지갑이 제시하는 **ID Token의 진위**와 **서명자 식별자(DID)**를 검증합니다.

#### ▶️ 시퀀스 다이어그램 (OID4VP 기준)

![SIOP 시퀀스](./siop.svg)

#### 🧠 설명 요약:

1. **Wallet**은 DID를 기반으로 JWT 서명
2. **Verifier**는 해당 DID를 resolve 하여 공개키 확보
3. **JWT의 서명과 Claim 유효성**을 검증하여 사용자의 소유권 확인

---

### 🔚 정리

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
