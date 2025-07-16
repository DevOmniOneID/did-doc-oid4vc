# OID4VC 분석서

- 주제 : OID4VC 분석서
- 작성 : 이수현 외 3명
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

<br>

### 4.2 OID4VCI
<br>

### 4.2.1 ODI4VCI 개요
### 4.2.1.1 OAuth 2.0 적용 범위

OID4VCI는 VC 발급 과정을 OAuth 2.0의 흐름에 맞춰 모델링함
- **Wallet**: OAuth 2.0의 `Client` 역할을 수행함
- **사용자 (End-User)**: `Resource Owner`로서 자신의 데이터에 대한 접근 권한을 Wallet에 부여함
- **Credential Issuer**: VC를 발급하는 주체로, `Resource Server`의 역할을 함
- **Authorization Server**: 사용자의 인증 및 동의를 처리하고 접근 토큰을 발급하는 `Authorization Server`이며, Credential Issuer가 이 역할을 겸할 수 있음

### 4.2.1.2 Authorization Code Flow vs. Pre-Authorized Code Flow

OID4VCI는 두 가지 주요 발급 흐름을 지원하여 다양한 시나리오에 대응함

- **Authorization Code Flow**: 사용자의 명시적인 인증과 동의가 필요한 전통적인 웹 기반 흐름으로, Wallet은 사용자를 Authorization Server로 리다이렉션하여 로그인 및 동의 절차를 거친 후, 발급에 필요한 토큰을 받음

![Authorization Code Flow](./oid4vci_authorization_code_flow.svg)

- **Pre-Authorized Code Flow**: 사용자가 이미 다른 채널(예: 이메일, SMS, 오프라인)을 통해 인증 및 동의를 완료했다고 가정하는 흐름으로, Wallet은 `Credential Offer`에 포함된 `pre-authorized_code`를 사용하여 즉시 토큰을 발급받으며, 사용자 리다이렉션 과정이 생략되어 UX가 간소화됨

![Pre-Authorized Code Flow](./oid4vci_pre_authorized_code_flow.svg)
---

- 
<br>

### 4.2.2 OID4VCI Endpoint

OID4VCI에서는 Verifiable Credential 발급을 위해 여러 개의 Endpoint가 정의됨
Credential Offer, Authorization, Token, Credential Endpoint는 기본 흐름을 구성하며,
Nonce, Deferred Credential, Notification Endpoint는 선택적으로 보안을 강화하거나 유연한 발급을 지원함

아래는 각 endpoint에 대한 발급 흐름을 도식화하였음

![Endpoint Flow](./oid4vc_endpoint_flow.png)

| Endpoint                     | 설명                                               | 비고                            |
|-----------------------------|----------------------------------------------------|---------------------------------|
| Credential Offer Endpoint   | VC 발급을 시작하는 제안 전달                       |                                 |
| Authorization Endpoint      | 사용자 인증 및 인가 (Authorization Code Flow)     | OAuth 2.0 표준                  |
| Token Endpoint              | Access Token 발급                                  | OAuth 2.0 표준                  |
| Nonce Endpoint              | VC 요청 서명을 위한 nonce 수령                    | 선택                            |
| Credential Endpoint         | VC 발급                                            | 필수                            |
| Deferred Credential Endpoint| 지연된 VC 재요청                                   | 선택                            |
| Notification Endpoint       | 발급된 Credential의 상태 변경(사용됨/삭제됨 등) 통지 | 선택                            |

* Credential Issuer Metadata 필드는 없지만, 표준 경로를 따라 조회하는 방식임
(RFC 8615 + OIDC4VCI 사양 11.2절 기반) URL 뒤에 /.well-known/openid-credential-issuer를 붙여서 접근
<br>


### 4.2.2.1 Credential Offer Endpoint

-   **개념:** Issuer가 Wallet에게 특정 Credential의 발급을 제안하기 위해 사용하는 시작점. 이 제안은 QR 코드, 링크 등 다양한 방식으로 전달될 수 있으며, Wallet이 발급 절차를 개시하는 데 필요한 정보를 담고 있음
-   **전달 방식:**
    -   `credential_offer`: Credential Offer 정보가 값으로 포함된 JSON 객체를 직접 전달함
    -   `credential_offer_uri`: Credential Offer 정보가 담긴 리소스를 가리키는 URL을 전달함. Wallet은 이 URI에 `GET` 요청을 보내 실제 Offer 정보를 가져와야 함. 이 방식은 QR 코드의 크기 제약을 피하는 데 유용함
-   **요청 (Request) - by URI:**
    ```http
    GET /credential-offer?credential_offer_uri=https%3A%2F%2Fcredential-issuer.example.com%2Foffer%2F12345
    Host: wallet.example.com
    ```
    *또는 Wallet이 `credential_offer_uri`에 직접 요청:*
    ```http
    GET /offer/12345 HTTP/1.1
    Host: credential-issuer.example.com
    ```
-   **응답 (Response) - by URI:**
    -   `credential_offer_uri` 사용 시, Issuer는 HTTP `200 OK`와 함께 `application/json` 형식의 Credential Offer 객체를 반환함
    -   **주요 파라미터:**
        -   `credential_issuer`: Issuer의 URL. Wallet은 이 URL을 사용하여 Issuer의 Metadata를 조회함
        -   `credential_configuration_ids`: 발급 제안된 Credential의 설정 ID 배열. Wallet은 이 ID를 사용하여 Metadata에서 상세 정보를 찾음
        -   `grants`: (선택 사항) Wallet이 사용할 수 있는 OAuth 2.0 Grant Type 정보
            -   `authorization_code`: 사용자의 명시적인 인증/동의가 필요한 경우 사용됨
            -   `urn:ietf:params:oauth:grant-type:pre-authorized_code`: 사용자의 사전 동의가 이미 완료된 경우 사용됨
    ```http
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "credential_issuer": "https://credential-issuer.example.com",
      "credential_configuration_ids": [
        "UniversityDegreeCredential"
      ],
      "grants": {
        "authorization_code": {
          "issuer_state": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        },
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
          "tx_code": {
            "length": 4,
            "input_mode": "numeric",
            "description": "Please provide the one-time code that was sent via e-mail"
          }
        }
      }
    }
    ```

### 4.2.2.2 Credential Issuer Metadata Endpoint

-   **개념:** Wallet이 Credential Issuer의 설정을 동적으로 발견하기 위해 사용하는 Endpoint. Issuer가 지원하는 자격증명 종류, 암호화 방식, Endpoint URL 등 VC 발급에 필요한 모든 정보를 제공함
-   **Endpoint:** `/.well-known/openid-credential-issuer`
-   **요청 (Request):**
    -   HTTP Method: `GET`
    -   Wallet은 Issuer의 식별자(URL)에 `/.well-known/openid-credential-issuer` 경로를 추가하여 Metadata를 요청함
    ```http
    GET /.well-known/openid-credential-issuer HTTP/1.1
    Host: credential-issuer.example.com
    Accept: application/json
    ```
-   **응답 (Response):**
    -   성공 시 HTTP `200 OK`와 함께 `application/json` 형식의 Metadata를 반환함
    -   **주요 파라미터:**
        -   `credential_issuer`: Issuer의 식별자 (URL)
        -   `credential_endpoint`: Credential을 발급하는 Endpoint URL
        -   `authorization_servers`: (선택 사항) Issuer가 신뢰하는 OAuth 2.0 Authorization Server의 식별자 배열
        -   `credential_configurations_supported`: 지원하는 Credential 종류 및 형식에 대한 상세 정보
        -   `deferred_credential_endpoint`: (선택 사항) 지연된 Credential 발급을 위한 Endpoint URL
        -   `nonce_endpoint`: (선택 사항) `c_nonce` 값을 얻기 위한 Endpoint URL
        -   `notification_endpoint`: (선택 사항) Credential 발급 완료 후 Wallet이 Issuer에게 알림을 보내는 Endpoint URL
    ```http
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "credential_issuer": "https://credential-issuer.example.com",
      "credential_endpoint": "https://credential-issuer.example.com/credential",
      "authorization_servers": ["https://auth-server.example.com"],
      "credential_configurations_supported": {
        "UniversityDegreeCredential": {
          "format": "jwt_vc_json",
          "scope": "UniversityDegree",
          "cryptographic_binding_methods_supported": ["did:example"],
          "credential_definition": {
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
          }
        }
      },
      "nonce_endpoint": "https://credential-issuer.example.com/nonce",
      "notification_endpoint": "https://credential-issuer.example.com/notification"
    }
    ```

### 4.2.2.3 Authorization Endpoint

-   **개념:** 표준 OAuth 2.0의 일부로, Wallet(Client)이 사용자의 동의를 얻어 Credential 발급에 대한 권한을 부여받는 Endpoint
-   **요청 방식:**
    1.  **`authorization_details` 사용 (권장):** 발급받을 Credential의 종류(`type`), 형식(`format`), 포함될 클레임(`claims`) 등 상세 정보를 JSON 구조로 명확하게 전달함. 여러 종류의 Credential을 동시에 요청하거나 복잡한 요청에 적합함
    2.  **`scope` 사용:** 발급받을 Credential을 단순한 문자열(scope)로 요청함. 간단한 요청에 사용될 수 있으며, 해당 scope의 의미는 Issuer의 Metadata에 정의되어 있어야 함
-   **요청 (Request) - `authorization_details` 사용 예시:**
    ```http
    GET /authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fwallet.example.org%2Fcb&authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22credential_configuration_id%22%3A%22UniversityDegreeCredential%22%7D%5D HTTP/1.1
    Host: auth-server.example.com
    ```
-   **요청 (Request) - `scope` 사용 예시:**
    ```http
    GET /authorize?response_type=code&client_id=...&scope=UniversityDegreeCredential HTTP/1.1
    Host: auth-server.example.com
    ```

-   **응답 (Response):**
    -   사용자 동의 시, HTTP `302 Found`와 함께 `redirect_uri`로 리다이렉션되며, 쿼리 파라미터로 `code` (Authorization Code)를 전달함
    ```http
    HTTP/1.1 302 Found
    Location: https://wallet.example.org/cb?code=Splx10BeZQQYbYS6WxSbIA&state=...
    ```

### 4.2.2.4 Token Endpoint

-   **개념:** 표준 OAuth 2.0의 일부로, Wallet이 `code` (Authorization Code 또는 Pre-Authorized Code)를 Access Token으로 교환하는 Endpoint
-   **요청 (Request) - Authorization Code 사용 예시:**
    ```http
    POST /token HTTP/1.1
    Host: auth-server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code
    &code=Splx10BeZQQYbYS6WxSbIA
    &redirect_uri=https%3A%2F%2Fwallet.example.org%2Fcb
    &client_id=s6BhdRkqt3
    &client_secret=...
    ```
-   **응답 (Response):**
    -   성공 시 HTTP `200 OK`와 함께 Access Token 정보를 담은 JSON 객체를 반환함
    -   **주요 파라미터:**
        -   `access_token`: Credential Endpoint에 접근하기 위한 Bearer 토큰
        -   `token_type`: "Bearer"
        -   `authorization_details`: (선택 사항) 발급 가능한 Credential에 대한 식별자(`credential_identifiers`) 등을 포함
    ```http
    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "2YotnFZFEjr1zCsicMWpAA",
      "token_type": "Bearer",
      "expires_in": 3600,
    }
    ```

### 4.2.2.5 Nonce Endpoint

-   **개념:** (선택 사항) Credential Request의 `proofs` 파라미터에 사용될 `c_nonce` 값을 얻기 위한 Endpoint. 이는 Replay 공격을 방지하는 데 중요한 역할을 함
-   **요청 (Request):**
    ```http
    POST /nonce HTTP/1.1
    Host: credential-issuer.example.com
    Content-Length: 0
    ```
-   **응답 (Response):**
    ```http
    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "c_nonce": "wKI4LT17ac15ES9bw8ac4",
      "c_nonce_expires_in": 86400
    }
    ```

### 4.2.2.6 Credential Endpoint

-   **개념:** Wallet이 Access Token을 사용하여 실제 Credential 발급을 요청하는 핵심 Endpoint
-   **요청 (Request):**
    -   `Authorization` 헤더에 `Bearer <access_token>`을 포함해야 함
    -   **요청 방식:**
        1.  **`credential_identifier` 사용:** Token Response의 `authorization_details`에서 받은 식별자를 사용하여 특정 Credential을 요청함
        2.  **`credential_configuration_id` 사용:** Token Response에 `authorization_details`가 없었을 경우, Authorization Request에서 사용했던 `scope`에 해당하는 `credential_configuration_id`를 사용함
    -   `proofs` 파라미터에 `c_nonce`를 포함한 암호학적 증명(e.g., JWT)을 전달하여 Credential을 특정 키에 바인딩하고 Replay 공격을 방지함
    ```http
    POST /credential HTTP/1.1
    Host: credential-issuer.example.com
    Content-Type: application/json
    Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA

    {
      "credential_identifier": "CivilEngineeringDegree-2023",
      "proofs": {
        "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2In0..."
      }
    }
    ```
-   **응답 (Response):**
    -   **즉시 발급:** HTTP `200 OK`와 함께 발급된 Credential 정보를 반환함
    -   **지연 발급:** HTTP `202 Accepted`와 함께 `transaction_id`와 재시도 간격(`interval`)을 반환함
    ```http
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "credentials": [{
        "credential": "eyJhbGciOiJFUzI1NiJ9...",
        "format": "jwt_vc_json"
      }],
      "c_nonce": "b1F2-2a78-4d4c",
      "notification_id": "3fwe98js"
    }
    ```

### 4.2.2.7 Deferred Credential Endpoint

-   **개념:** (선택 사항) Credential Endpoint에서 `transaction_id`를 받은 경우, Wallet이 주기적으로 Credential 발급 완료 여부를 확인하고 최종적으로 Credential을 수령하기 위해 사용하는 Endpoint
-   **요청 (Request):**
    ```http
    POST /credential_deferred HTTP/1.1
    Host: credential-issuer.example.com
    Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA

    {
      "transaction_id": "8xL0xBtZp8"
    }
    ```
-   **응답 (Response):**
    -   **발급 완료:** HTTP `200 OK`와 함께 Credential 정보를 반환함
    -   **아직 대기 중:** HTTP `202 Accepted`와 함께 다음 요청까지 대기할 시간을 `interval` 파라미터로 다시 반환함

### 4.2.2.8 Notification Endpoint

-   **개념:** (선택 사항) Wallet이 Credential의 수신 상태(성공, 실패, 삭제 등)를 Issuer에게 알리기 위해 사용하는 Endpoint
-   **요청 (Request):**
    ```http
    POST /notification HTTP/1.1
    Host: credential-issuer.example.com
    Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA

    {
      "notification_id": "3fwe98js",
      "event": "credential_accepted"
    }
    ```
-   **응답 (Response):**
    -   성공적으로 알림을 수신하면 HTTP `204 No Content`를 반환하는 것이 권장됨

---

<br>

### 4.2.3 OID4VCI Issuer Metadata

발급자 메타데이터는 OID4VCI의 동적 상호운용성을 가능하게 하는 핵심 요소임. Wallet은 이 정보를 통해 발급자의 정책과 기술 사양을 파악하고 그에 맞춰 동작함

- **조회 경로**: `https://{credential_issuer}/.well-known/openid-credential-issuer`
- **주요 필드 상세 설명**
    - `credential_issuer` (필수): 메타데이터를 제공하는 발급자의 URL
    - `authorization_servers` (선택): 발급자가 신뢰하는 AS의 식별자 배열. 생략 시 발급자가 AS 역할을 겸함
    - `credential_endpoint` (필수): VC 발급 요청 엔드포인트
    - `deferred_credential_endpoint` (선택): 지연된 VC 조회 엔드포인트
    - `nonce_endpoint` (선택): 발급시 필요한 c_nonce를 획득하는 엔드포인트
    - `notification_endpoint` (선택): 발급상태를 알리는 엔드포인트
    - `credentials_supported` (필수): 발급 가능한 VC 목록과 각 VC의 상세 사양을 담은 객체
        - **객체 키**: `credential_configuration_ids`와 매핑되는 고유 식별자
        - **객체 값**:
            - `format`: `jwt_vc_json`, `ldp_vc`, `mso_mdoc` 등 VC 포맷
            - `cryptographic_binding_methods_supported`: `jwk`, `did` 등 Holder 키 바인딩 방식
            - `proof_types_supported`: `jwt`, `ldp_vp` 등 지원하는 증명(proof) 타입
            - `display`: VC의 이름, 로고, 색상 등 UI 정보
            - `credential_definition`: VC의 `types` (`VerifiableCredential`, `UniversityDegreeCredential` 등)과 `claims`에 대한 상세 설명
    - `display` (선택): 발급 기관의 이름, 로고 등 UI에 표시될 정보

- **예시**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "credential_issuer": "https://issuer.example.com",

  "credential_endpoint": "https://issuer.example.com/credential",
  "deferred_credential_endpoint": "https://issuer.example.com/deferred",
  "nonce_endpoint": "https://issuer.example.com/nonce",
  "notification_endpoint": "https://issuer.example.com/notify",

  "credential_response_encryption_alg_values_supported": ["ECDH-ES"],
  "credential_response_encryption_enc_values_supported": ["A256GCM"],

  "token_endpoint": "https://issuer.example.com/token",
  "authorization_server": "https://auth.example.com",  // 인가 서버 분리 시

  "credential_configurations_supported": {
    "UniversityDegreeCredential": {
      "format": "vc+sd-jwt",
      "scope": "UniversityDegreeCredential",
      "cryptographic_binding_methods_supported": ["did"],
      "credential_definition": {
        "type": ["UniversityDegreeCredential"],
        "trusted_issuers": ["did:example:issuer123"]
      }
    },
    "mDL": {
      "format": "iso/18013-5",
      "scope": "org.iso.18013.5.1.mDL",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_definition": {
        "doctype": "org.iso.18013.5.1.mDL"
      }
    }
  }
}
```

---

### 4.2.4 Security Considerations

OID4VCI는 안전한 VC 발급을 위해 여러 보안 메커니즘을 정의함

- **소유자 증명 (Holder Binding)**: `Credential Request`의 `proof` 파라미터는 VC가 정당한 소유자에게 발급되도록 보장함. Holder의 개인키로 서명된 증명을 통해 발급자는 요청자가 VC에 포함될 공개키의 소유자임을 확인함
- **재전송 공격 방지**: `c_nonce`는 토큰과 VC 요청을 한 번의 트랜잭션으로 묶어 재전송 공격을 방지함. 토큰 발급 시 받은 `c_nonce`는 VC 요청 `proof`에 포함되어야 하며, 한 번 사용된 `c_nonce`는 다시 사용할 수 없음
- **피싱 공격 방지**: Pre-authorized code flow에서 `tx_code`(PIN 등)를 사용하여 QR 코드 탈취(shoulder surfing) 후 다른 기기에서 토큰을 발급받으려는 공격을 막을 수 있음
- **전송 계층 보안**: 모든 통신은 TLS(Transport Layer Security)로 암호화되어야 함
- **Credential Offer 보안**: `Credential Offer` 자체는 서명되지 않은 정보이므로, Wallet은 Offer의 `credential_issuer` 정보를 신뢰하지 않고, 해당 URL의 메타데이터 엔드포인트(`.well-known`)를 직접 조회하여 발급자를 검증해야 함
<br>


### 4.3 OID4VP // 아래 세부 목차는 자유롭게 바꾸셔도 됩니다.
### 4.3.1 Verifier Request Object 처리
### 4.3.2 DCQL 쿼리 처리 및 VP 구성
### 4.3.3 Response Mode 유형 및 처리 방식
### 4.3.4 VP Token 생성 및 서명
### 4.3.5 제출 흐름별 UX 설계 (Cross / Same Device)

### 4.4 SIOPv2

### 4.4.1 개요 및 역할

**SIOPv2 (Self-Issued OpenID Provider v2)** 는 사용자가 자기 자신을 OpenID Provider로 삼아, **중앙 ID 제공자 없이 스스로 인증을 수행하는 분산 신원 인증 모델** 이다.

- 기존의 Google, Facebook 같은 중앙화된 IDP 구조를 대체
- 사용자가 직접 **ID Token을 생성**하고, 이를 제시함으로써 **자기주권형 신원(Self-Sovereign Identity, SSI)** 실현
- OpenID Connect(OIDC)의 흐름을 그대로 따르므로 기존 생태계와의 호환성 확보

**핵심 포인트:**
- 사용자가 직접 서명한 JWT ID Token(DIDAuth와 유사)을 발급
- DID 기반으로 사용자를 식별 및 검증, OIDC 확장 구조
- VC 발급 요청(OID4VCI) 또는 VC 제시(OID4VP) 시에 인증 주체로 사용됨

---

### 4.4.2 **OID4VCI** 에서의 Client Authentication 방식으로 사용

OID4VCI에서 사용자는 Credential Issuer에게 VC 발급을 요청한다.  
이때 Issuer는 요청자의 신원을 확인해야 하며, **Client Authentication** 방식으로 **SIOP 기반 ID Token** (사용자의 식별자 기능)이 활용된다. 

##### 흐름 요약:
1. 사용자가 지갑을 통해 VC 발급 요청
2. 지갑은 **SIOP 방식으로 ID Token 생성**
3. Credential Issuer는 해당 ID Token을 검증하여 사용자 식별 및 인증 수행

> 기존 `client_secret`, `client_assertion` 방식 대신 사용자가 **직접 서명한 ID Token**을 사용하는 방식

---

### 4.4.3 **OID4VP** 에서의 Subject 인증 방식으로 사용

OID4VP는 사용자가 VC를 제시할 때, Verifier가 **누가 제시했는가** 를 검증해야 한다.
이때 SIOPv2는 **VC의 제시 주체(Subject)** 인증 수단으로 사용된다.

#### 간략 인증 흐름:
1. Verifier가 Presentation Request 전송
2. Wallet이 **SIOPv2 방식의 ID Token** 생성
3. VP와 함께 Verifier에게 전달
4. Verifier는 ID Token의 서명을 확인하고, DID를 통해 소유자 식별


#### 서비스 이용시 인증 흐름:
![SIOP 시퀀스](./siop_seq.svg)

---

### 4.4.4 ID Token 발급 구조 (JWT + DID)

SIOPv2에서 발급하는 ID Token은 다음과 같은 **JWT 구조**를 가진다:

#### JWT 구성:

##### Header
```json
{
  "alg": "ES256K",
  "typ": "JWT",
  "kid": "did:wallet:123#key-1"
}
```

##### Payload (예시)
```json
{
  "iss": "did:wallet:123",
  "sub": "did:wallet:123",
  "aud": "https://verifier.example.org",
  "iat": 1689456000,
  "exp": 1689463200,
  "sub_jwk": {   // 공개키 정보
    "kty": "EC",
    "crv": "secp256k1",
    "x": "...",
    "y": "..."
  },
  "vp_token": {VC, VP 포함 가능}  // 옵션
}
```

##### Signature
- DID Document에 등록된 wallet의 개인키로 서명
- 공개키는 DID를 통해 검증 가능

---

### 4.4.5 SIOP 기반 Wallet의 검증 흐름

월렛이 인증 주체로 동작할 때, Verifier 또는 Credential Issuer는 월렛이 제시하는 **ID Token의 진위**와 **서명자 식별자(DID)** 를 검증한다.

#### 시퀀스 다이어그램 (OID4VP 기준)

![SIOP 시퀀스](./siop.svg)

#### 설명 요약:

1. **Wallet**은 DID를 기반으로 JWT 서명
2. **Verifier**는 해당 DID를 resolve 하여 공개키 확보
3. **JWT의 서명과 Claim 유효성**을 검증하여 사용자의 소유권 확인

---

### 정리

| 항목 | 설명 |
|------|------|
| **SIOPv2** | 사용자가 직접 인증 주체가 되는 분산 ID 방식 |
| **OID4VCI** | VC 발급 시 지갑이 ID Token을 이용해 자신을 인증 |
| **OID4VP** | VC 제시 시 지갑이 제시자의 신원을 ID Token으로 증명 |
| **ID Token 구조** | JWT 형식, DID 기반 발급자, 서명 포함 |
| **검증 흐름** | DID → 공개키 → JWT 서명 및 Claim 검증 |

> **SIOPv2는 Self-Sovereign Identity 실현을 위한 핵심 구성요소로, 신뢰 가능한 자기주권형 인증을 구현함.**




## 5. OID4VC 적용 전략


## 6. 부록
