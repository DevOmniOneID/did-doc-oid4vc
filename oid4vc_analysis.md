# OID4VC 분석서

- 주제 : OID4VC 분석서
- 작성 : 이수현, 현다은, 박동준, 김상준
- 일자 : 2025-07-18
- 버전 : v1.0.0

| 버전 | 일자       | 변경         |
| ------- | ---------- | --------------- |
| v1.0.0  | 2025-07-18 | 최초 작성 |

## 목차

1. [범위 및 목표](#1-범위-및-목표)
2. [요구사항 도출](#2-요구사항-도출)
   - 2.1 [기능 요구사항](#21-기능-요구사항)
   - 2.2 [비기능 요구사항](#22-비기능-요구사항)
3. [목표 시스템 구성 (System Context Diagram)](#3-목표-시스템-구성-system-context-diagram)
   - 3.1 [VC 발급](#31-vc-발급)
   - 3.2 [VP 제출](#32-vp-제출)
4. [OID4VC 분석 결과](#4-oid4vc-분석-결과)
   - 4.1 [OID4VCI](#41-oid4vci)
     - 4.1.1 [OID4VCI 개요](#411-oid4vci-개요)
     - 4.1.2 [OID4VCI Endpoint](#412-oid4vci-endpoint)
     - 4.1.3 [OID4VCI Issuer Metadata](#413-oid4vci-issuer-metadata)
     - 4.1.4 [고려사항](#414-고려사항)
   - 4.2 [OID4VP](#42-oid4vp)
     - 4.2.1 [OID4VP 개요](#421-oid4vp-개요)
     - 4.2.2 [Cross Device Flow vs. Same Device Flow](#422-cross-device-flow-vs-same-device-flow)
     - 4.2.3 [OID4VP Redirect 기반 요청-응답 구조](#423-oid4vp-redirect-기반-요청-응답-구조)
     - 4.2.4 [OID4VP Verifier Metadata](#424-oid4vp-verifier-metadata)
     - 4.2.5 [OID4VP DCQL](#425-oid4vp-dcql)
     - 4.2.6 [OID4VP VP Token](#426-oid4vp-vp-token)
     - 4.2.7 [고려사항](#427-고려사항)
   - 4.3 [SIOPv2](#43-siopv2)
     - 4.3.1 [개요 및 역할](#431-개요-및-역할)
     - 4.3.2 [OID4VCI에서의 Client Authentication 방식으로 사용](#432-oid4vci에서의-client-authentication-방식으로-사용)
     - 4.3.3 [OID4VP에서의 Subject 인증 방식으로 사용](#433-oid4vp에서의-subject-인증-방식으로-사용)
     - 4.3.4 [ID Token 발급 구조 (JWT + DID)](#434-id-token-발급-구조-jwt--did)
     - 4.3.5 [SIOP 기반 Wallet의 검증 흐름](#435-siop-기반-wallet의-검증-흐름)
5. [OID4VC 적용 전략](#5-oid4vc-적용-전략)
     - 5.1 [개요](#51-개요)
     - 5.2 [목표 시스템 아키텍처](#52-목표-시스템-아키텍처)
     - 5.3 [신규 개발 요구사항](#53-신규-개발-요구사항)
     - 5.4 [OID4VC 적용 전략](#54-oid4vc-적용-전략)
     - 5.5 [결론](#55-결론)
6. [부록](#6-부록)
   - 6.1 [개요](#61-개요)
     - 6.1.1 [JWT (JSON Web Token)](#611-jwt-json-web-token)
     - 6.1.2 [JWS (JSON Web Signature)](#612-jws-json-web-signature)
     - 6.1.3 [JWE (JSON Web Encryption)](#613-jwe-json-web-encryption)
     - 6.1.4 [JWK (JSON Web Key)](#614-jwk-json-web-key)
   - 6.2 [OID4VCI 기반 encVC 발급 과정 예시 (ECDH 예시)](#62-oid4vci-기반-encvc-발급-과정-예시-ecdh-예시)

## 1. 범위 및 목표

OID4VC 도입 및 적용을 통해 EUDIW(EU Digital Identity Wallet) 등 다양한 디지털 월렛과의 연동을 목표로 상호운용성을 개선한다. 또한 OpenID와 OAuth 2.0 등 국제적으로 검증된 개방형 표준 프로토콜을 기반으로 전체 시스템을 구조화 및 고도화한다. 이와 함께 기존 Open DID의 레거시 요소를 정비할 수 있는 기회로 OID4VC를 활용하여 기존의 기술부채를 해소하고 기술적 고도화와 함께 Open DID의 가치를 더욱 향상시키는 것을 목표로 한다.
- **(상호운용성 개선)** : EUDIW(EU Digital Identity Wallet) 등과의 호환성 확보
- **(개방형 표준 준수)** : OpenID 및 OAuth 2.0 등 개방형 표준 프로토콜 기반 규격화
- **(기술부채 해결)** : 프로토콜 도입을 통한 기존 Legacy 기술요소 고도화
![OID4VC](./images/goals.png)

## 2. 요구사항 도출

### 2.1 기능 요구사항

| **구분**     | 항목                                       | 설명                                                                 |
|--------------|--------------------------------------------|----------------------------------------------------------------------|
| **인가/인증** | OAuth 2.0 지원                              | OAuth 2.0 표준 프로토콜 지원, 클라이언트 등록 및 PKCE 지원 등       |
|              | Authorization Server 구현                   | OAuth 2.0 표준 엔드포인트 제공 서버 구현, Access Token 발급 및 검증 기능, Refresh Token 구현 등 |
|              | TLS 적용                                    | 인증 및 데이터 전송 전 구간에 HTTPS 적용(TLS 1.2 이상 필수) 등     |
|              | App Scheme 지원                             | Native App 연동을 위한 Custom URI 및 App Scheme 지원               |
|              | SIOPv2 지원                                 | SIOPv2 표준에 따라 사용자 DID 기반 ID Token 발급 등                |
|              | OIDC Provider 구현                          | 월렛에서의 ID Token 발급을 위한 OIDC Provider 구현 등              |
| **VC 발급**   | Issuer Endpoint 구현                        | OID4VCI 표준 Endpoint 구현 등                                       |
|              | Issuer Metadata 제공                        | Profile 정보에 해당하는 Metadata 제공 등                           |
|              | OID4VCI Pre-authorized code 프로토콜 적용   | Pre-authorized code 프로토콜 기반 VC 발급 플로우 지원 등           |
|              | OID4VCI Authorization code 프로토콜 적용    | Authorization code 프로토콜 기반 VC 발급 플로우 지원 등            |
| **VP 제출**   | Verifier Endpoint 구현                      | OID4VP 표준 Endpoint 구현 등                                       |
|              | DCQL 지원                                   | Profile 정보 제공 등을 위한 Digital Credentials Query Language 지원 등 |
|              | OID4VP Cross Device 프로토콜 적용          | Cross Device 프로토콜 기반 VP 제출 플로우 지원 등                  |
|              | OID4VP Same Device 프로토콜 적용           | Same Device 프로토콜 기반 VP 제출 플로우 지원 등                   |
| **데이터 모델**| JWT 적용                                   | VC, VP, ID Token 등 모든 핵심 메시지를 JWT 형식으로 처리 등        |
|              | JWK / JWE 지원                              | 공개키 교환을 위한 JWK 지원, ECDH 기반 Payload 암호화를 위한 JWE 지원 등 |

### 2.2 비기능 요구사항

| **구분**       | 항목                             | 설명                                                                                 |
|----------------|----------------------------------|--------------------------------------------------------------------------------------|
| **보안성**     | 세션 계층 암호화                 | OAuth 2.0 표준에 따라 모든 https 통신은 TLS 1.2 이상을 적용하여 세션 계층에서 암호화를 보장해야 함 |
|                | 토큰 관리                        | Access Token, Refresh Token의 저장, 검증, 만료 정책 및 재사용 방지 등 보안 정책을 관리해야 함 |
| **상호운용성** | OID4VC 표준 준수                 | OID4VCI, OID4VP, SIOPv2 등 OpenID 관련 스펙을 준수해야 하며 향후 표준 변경에도 유연하게 대응 가능해야 함 |
|                | 다양한 Wallet과의 호환성        | EU의 EUDI Wallet 등 다양한 DID Wallet과 상호운용 가능한 구조여야 함                 |
| **확장성**     | mDoc 스펙 확장 가능성           | ISO/IEC 18013-5 등 mDL/mDocs 표준과의 연계 확장이 가능해야 함                      |
| **신뢰성**     | 책임 추적성                      | Access Token 등에 대한 로깅을 통해 식별자 기반 추적이 가능해야 함                  |
| **사용성**     | 사용자 지향 인터페이스           | 사용자 지향 인터페이스 제공으로 신규 스펙 적용에 따른 UX 저해가 없어야 함          |

## 3. 목표 시스템 구성 (System Context Diagram)

목표 시스템의 구성을 시각화하기 위한 여러 다이어그램 작성 방법론 중 가장 적합한 다이어그램으로서 System Context Diagram을 채택하였다.
해당 다이어그램은 시스템의 전체적인 맥락을 보여주며, 특히 신규 채택되는 OID4VC 시스템의 역할을 한 눈에 확인할 수 있다. 추가적으로 사용자의 역할과 외부 시스템과의 관계 또한 용이하게 파악할 수 있다.

### 3.1 VC 발급

![SYSTEM_CONTEXT_DIAGRAM_OID4VCI](./images/system_context_diagram_oid4vci.png)
목표 시스템 구성에 있어서 VC 발급 관점에서의 Context Diagram은 아래와 같은 상호 작용을 포함한다.

- **A. Authorization Request** : Holder가 Resource Owner로서 발급에 동의하기 위해 Wallet이 Authorization Request를 보낸다. 일반적으로 Authorization Code Flow가 사용된다.
- **B. Authorization Grant** : Holder가 동의한 후 Authorization Server로부터 Authorization Code를 Wallet이 전달 받는다. 해당 절차에는 Authorization Server로의 로그인 과정 등이 포함된다. 여기서는 이후의 구체적인 흐름은 생략하였다.
- **C. Authorization Grant 전달** : Wallet은 받은 Authorization Code를 Authorization Server에 전달하여 Access Token을 요청한다.
- **D. Access Token 수신** : Authorization Server는 유효한 Authorization Code를 확인한 뒤 Access Token을 Wallet에 발급한다.
- **E. Credential Request (Access Token 포함)** : Wallet은 Access Token을 포함하여 Issuer에게 Credential Request를 보낸다. 이때 요청은 OID4VCI 표준을 따른다.
- **F. VC 응답 (Protected Resource)** : Issuer는 요청된 Credential을 검증한 후 Verifiable Credentials을 Wallet에 반환한다.

### 3.2 VP 제출

![SYSTEM_CONTEXT_DIAGRAM_OID4VP](./images/system_context_diagram_oid4vp.png)
목표 시스템 구성에 있어서 VP 제출 관점에서의 Context Diagram은 아래와 같은 상호 작용을 포함한다.

- **A. Interacts** : Holder는 웹 브라우저 등을 통해 Verifier와 상호작용한다. 이때 Verifier는 VP 제출을 요구하며 해당 Authorization Request를 담은 QR 코드 등을 생성한다.
- **B. Authorization Request** : Holder는 해당 QR 코드 등을 Cross Device 환경의 Wallet에서 스캔한다. 이에 따라 Wallet은 Verifier가 제공한 Authorization Request를 수신하고 처리할 준비를 한다.
- **C. End-User Authentication / Consent** : Wallet은 Holder에게 본인의 VC 사용에 대한 인증 및 동의 절차를 요구한다. PIN 입력 등의 방식으로 Holder의 명시적 동의를 획득한다.
- **D. VP 제출 (VP Token)** : Holder가 동의하면 Wallet은 Verifier가 요구한 항목을 충족하는 Verifiable Presentations를 생성하여 제출한다. 해당 데이터는 VP Token의 형태로서 OID4VP 프로토콜에 따라 서명되고 암호화된 형태로 안전하게 전달된다.

## 4. OID4VC 분석 결과

### 4.1 OID4VCI

OID4VCI(OpenID for Verifiable Credential Issuance)는 OAuth 2.0 기반의 표준화된 방식으로 VC를 발급받을 수 있도록 정의한 프로토콜로써 Wallet은 OAuth 클라이언트로 동작하며, Credential Issuer와 Authorization Server를 통해 VC를 안전하게 수령한다.
이 표준은 다양한 포맷과 발급 흐름을 지원하여 상호운용성과 보안을 모두 고려한다.

#### 4.1.1 OID4VCI 개요

##### 4.1.1.1 OAuth 2.0 적용 범위

OID4VCI는 VC 발급 과정을 OAuth 2.0의 흐름에 맞춰 모델링한다.
- **Wallet**: OAuth 2.0의 `Client` 역할을 수행한다.
- **사용자 (End-User)**: `Resource Owner`로서 자신의 데이터에 대한 접근 권한을 Wallet에 부여한다.
- **Credential Issuer**: VC를 발급하는 주체로, `Resource Server`의 역할을 한다.
- **Authorization Server**: 사용자의 인증 및 동의를 처리하고 접근 토큰을 발급하는 `Authorization Server`이며, Credential Issuer가 이 역할을 겸할 수 있다.

##### 4.1.1.2 Authorization Code Flow vs. Pre-Authorized Code Flow

OID4VCI는 두 가지 주요 발급 흐름을 지원하여 다양한 시나리오에 대응한다.

- **Authorization Code Flow**: 사용자의 명시적인 인증과 동의가 필요한 전통적인 웹 기반 흐름으로, Wallet은 사용자를 Authorization Server로 리다이렉션하여 로그인 및 동의 절차를 거친 후, 발급에 필요한 토큰을 받는다.

![Authorization Code Flow](./images/oid4vci_authorization_code_flow.svg)

- **Pre-Authorized Code Flow**: 사용자가 이미 다른 채널(예: 이메일, SMS, 오프라인)을 통해 인증 및 동의를 완료했다고 가정하는 흐름으로, Wallet은 `Credential Offer`에 포함된 `pre-authorized_code`를 사용하여 즉시 토큰을 발급받으며, 사용자 리다이렉션 과정이 생략되어 UX가 간소화된다.

![Pre-Authorized Code Flow](./images/oid4vci_pre_authorized_code_flow.svg)

<br>

#### 4.1.2 OID4VCI Endpoint

OID4VCI에서는 Verifiable Credential 발급을 위해 여러 개의 Endpoint가 정의된다.
Credential Offer, Authorization, Token, Credential Endpoint는 기본 흐름을 구성하며,
Nonce, Deferred Credential, Notification Endpoint는 선택적으로 보안을 강화하거나 유연한 발급을 지원한다.

아래는 각 endpoint에 대한 발급 흐름을 도식화하였다.

![Endpoint Flow](./images/oid4vc_endpoint_flow.png)

| Endpoint                     | 설명                                               | 비고                            |
|-----------------------------|----------------------------------------------------|---------------------------------|
| Credential Offer Endpoint   | VC 발급을 시작하는 제안 전달                       |                                 |
| Authorization Endpoint      | 사용자 인증 및 인가 (Authorization Code Flow)     | OAuth 2.0 표준                  |
| Token Endpoint              | Access Token 발급                                  | OAuth 2.0 표준                  |
| Nonce Endpoint              | VC 요청 서명을 위한 nonce 수령                    | 선택                            |
| Credential Endpoint         | VC 발급                                            | 필수                            |
| Deferred Credential Endpoint| 지연된 VC 재요청                                   | 선택                            |
| Notification Endpoint       | 발급된 Credential의 상태 변경(사용됨/삭제됨 등) 통지 | 선택                            |

* Credential Issuer Metadata 필드는 없지만, 표준 경로를 따라 조회하는 방식이다.
(RFC 8615 + OIDC4VCI 사양 11.2절 기반) URL 뒤에 /.well-known/openid-credential-issuer를 붙여서 접근한다.

<br>

##### 4.1.2.1 Credential Offer Endpoint

-   **개념:** Issuer가 Wallet에게 특정 Credential의 발급을 제안하기 위해 사용하는 시작점. 이 제안은 QR 코드, 링크 등 다양한 방식으로 전달될 수 있으며, Wallet이 발급 절차를 개시하는 데 필요한 정보를 담고 있다.
-   **전달 방식:**
    -   `credential_offer`: Credential Offer 정보가 값으로 포함된 JSON 객체를 직접 전달한다.
    -   `credential_offer_uri`: Credential Offer 정보가 담긴 리소스를 가리키는 URL을 전달한다. Wallet은 이 URI에 `GET` 요청을 보내 실제 Offer 정보를 가져와야 한다. 이 방식은 QR 코드의 크기 제약을 피하는 데 유용하다.
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
    -   `credential_offer_uri` 사용 시, Issuer는 HTTP `200 OK`와 함께 `application/json` 형식의 Credential Offer 객체를 반환한다.
    -   **주요 파라미터:**
        -   `credential_issuer`: Issuer의 URL. Wallet은 이 URL을 사용하여 Issuer의 Metadata를 조회한다.
        -   `credential_configuration_ids`: 발급 제안된 Credential의 설정 ID 배열. Wallet은 이 ID를 사용하여 Metadata에서 상세 정보를 찾는다.
        -   `grants`: (선택 사항) Wallet이 사용할 수 있는 OAuth 2.0 Grant Type 정보
            -   `authorization_code`: 사용자의 명시적인 인증/동의가 필요한 경우 사용된다.
            -   `urn:ietf:params:oauth:grant-type:pre-authorized_code`: 사용자의 사전 동의가 이미 완료된 경우 사용된다.
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

##### 4.1.2.2 Credential Issuer Metadata Endpoint

-   **개념:** Wallet이 Credential Issuer의 설정을 동적으로 발견하기 위해 사용하는 Endpoint. Issuer가 지원하는 자격증명 종류, 암호화 방식, Endpoint URL 등 VC 발급에 필요한 모든 정보를 제공한다.
-   **Endpoint:** `/.well-known/openid-credential-issuer`
-   **요청 (Request):**
    -   HTTP Method: `GET`
    -   Wallet은 Issuer의 식별자(URL)에 `/.well-known/openid-credential-issuer` 경로를 추가하여 Metadata를 요청한다.
    ```http
    GET /.well-known/openid-credential-issuer HTTP/1.1
    Host: credential-issuer.example.com
    Accept: application/json
    ```
-   **응답 (Response):**
    -   성공 시 HTTP `200 OK`와 함께 `application/json` 형식의 Metadata를 반환한다.
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

##### 4.1.2.3 Authorization Endpoint

-   **개념:** 표준 OAuth 2.0의 일부로, Wallet(Client)이 사용자의 동의를 얻어 Credential 발급에 대한 권한을 부여받는 Endpoint
-   **요청 방식:**
    1.  **`authorization_details` 사용 (권장):** 발급받을 Credential의 종류(`type`), 형식(`format`), 포함될 클레임(`claims`) 등 상세 정보를 JSON 구조로 명확하게 전달한다. 여러 종류의 Credential을 동시에 요청하거나 복잡한 요청에 적합하다.
    2.  **`scope` 사용:** 발급받을 Credential을 단순한 문자열(scope)로 요청함. 간단한 요청에 사용될 수 있으며, 해당 scope의 의미는 Issuer의 Metadata에 정의되어 있어야 한다.
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
    -   사용자 동의 시, HTTP `302 Found`와 함께 `redirect_uri`로 리다이렉션되며, 쿼리 파라미터로 `code` (Authorization Code)를 전달한다.
    ```http
    HTTP/1.1 302 Found
    Location: https://wallet.example.org/cb?code=Splx10BeZQQYbYS6WxSbIA&state=...
    ```

##### 4.1.2.4 Token Endpoint

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
    -   성공 시 HTTP `200 OK`와 함께 Access Token 정보를 담은 JSON 객체를 반환한다.
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

##### 4.1.2.5 Nonce Endpoint

-   **개념:** (선택 사항) Credential Request의 `proofs` 파라미터에 사용될 `c_nonce` 값을 얻기 위한 Endpoint. 이는 Replay 공격을 방지하는 데 중요한 역할을 한다.
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

##### 4.1.2.6 Credential Endpoint

-   **개념:** Wallet이 Access Token을 사용하여 실제 Credential 발급을 요청하는 핵심 Endpoint
-   **요청 (Request):**
    -   `Authorization` 헤더에 `Bearer <access_token>`을 포함해야 한다.
    -   **요청 방식:**
        1.  **`credential_identifier` 사용:** Token Response의 `authorization_details`에서 받은 식별자를 사용하여 특정 Credential을 요청한다.
        2.  **`credential_configuration_id` 사용:** Token Response에 `authorization_details`가 없었을 경우, Authorization Request에서 사용했던 `scope`에 해당하는 `credential_configuration_id`를 사용한다.
    -   `proofs` 파라미터에 `c_nonce`를 포함한 암호학적 증명(e.g., JWT)을 전달하여 Credential을 특정 키에 바인딩하고 Replay 공격을 방지한다.
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
    -   **즉시 발급:** HTTP `200 OK`와 함께 발급된 Credential 정보를 반환한다.
    -   **지연 발급:** HTTP `202 Accepted`와 함께 `transaction_id`와 재시도 간격(`interval`)을 반환한다.
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

##### 4.1.2.7 Deferred Credential Endpoint

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
    -   **발급 완료:** HTTP `200 OK`와 함께 Credential 정보를 반환한다.
    -   **아직 대기 중:** HTTP `202 Accepted`와 함께 다음 요청까지 대기할 시간을 `interval` 파라미터로 다시 반환한다.

##### 4.1.2.8 Notification Endpoint

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
    -   성공적으로 알림을 수신하면 HTTP `204 No Content`를 반환하는 것이 권장된다.

<br>

#### 4.1.3 OID4VCI Issuer Metadata

발급자 메타데이터는 OID4VCI의 동적 상호운용성을 가능하게 하는 핵심 요소이다. Wallet은 이 정보를 통해 발급자의 정책과 기술 사양을 파악하고 그에 맞춰 동작한다.

- **조회 경로**: `https://{credential_issuer}/.well-known/openid-credential-issuer`
- **주요 필드 상세 설명**
    - `credential_issuer` (필수): 메타데이터를 제공하는 발급자의 URL
    - `authorization_servers` (선택): 발급자가 신뢰하는 AS의 식별자 배열. 생략 시 발급자가 AS 역할을 겸한다.
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

#### 4.1.4 고려사항

##### 4.1.4.1 보안 고려사항 (Security Considerations)

- **소유자 증명 (Holder Binding)**: `Credential Request`의 `proof` 파라미터는 VC가 정당한 소유자에게 발급되도록 보장함. Holder의 개인키로 서명된 증명을 통해 발급자는 요청자가 VC에 포함될 공개키의 소유자임을 확인한다.
- **재전송 공격 방지**: `c_nonce`는 토큰과 VC 요청을 한 번의 트랜잭션으로 묶어 재전송 공격을 방지함. 토큰 발급 시 받은 `c_nonce`는 VC 요청 `proof`에 포함되어야 하며, 한 번 사용된 `c_nonce`는 다시 사용할 수 없다.
- **피싱 공격 방지**: Pre-authorized code flow에서 `tx_code`(PIN 등)를 사용하여 QR 코드 탈취(shoulder surfing) 후 다른 기기에서 토큰을 발급받으려는 공격을 막을 수 있다.
- **전송 계층 보안**: 모든 통신은 TLS(Transport Layer Security)로 암호화되어야 한다.
- **Credential Offer 보안**: `Credential Offer` 자체는 서명되지 않은 정보이므로, Wallet은 Offer의 `credential_issuer` 정보를 신뢰하지 않고, 해당 URL의 메타데이터 엔드포인트(`.well-known`)를 직접 조회하여 발급자를 검증해야 한다.

##### 4.1.4.2 구현 고려사항 (Implementation Considerations)

-   **자격 증명 바인딩**: VC 소유자에게 VC를 바인딩하는 방법으로 클레임 기반 바인딩(암호화 키 없이 클레임으로 소유 확인)과 베어러 자격 증명(소유 증명 없이 제시)이 있다.
-   **자격 증명 엔드포인트 접근**: 동일한 액세스 토큰으로 여러 번 접근 가능하며, 발급자는 갱신 여부 및 재인증 필요성을 결정한다.
-   **발급자 식별자 관계**: 메타데이터의 HTTPS URL 발급자 식별자와 VC 내 발급자 식별자(DID 등) 간의 바인딩을 Wallet이 확인할 수 있어야 한다.
-   **자격 증명 갱신**: Wallet은 유효한 액세스/갱신 토큰으로 VC를 업데이트하거나, 발급자가 재발급 프로세스를 시작하여 VC를 갱신할 수 있다.
-   **사양 의존성**: 현재 최종 사양이 아닌 여러 사양(OpenID Federation, SD-JWT VC 등)에 의존하고 있음을 인지해야 한다. (draft) 

##### 4.1.4.3 개인 정보 보호 고려사항 (Privacy Considerations)

-   **원칙 준수**: [RFC9396] 및 [ISO.29100]의 개인 정보 보호 원칙을 준수해야 한다.
-   **사용자 동의**: VC 발급 전 최종 사용자에게 정보 포함 내용 및 목적을 명확히 설명하고 동의를 얻어야 한다.
-   **최소 공개**: 불필요한 클레임 노출 방지를 위해 선택적 공개를 지원하거나 각 클레임별 VC 발급을 고려해야 한다.
-   **자격 증명 저장**: 최종 사용자 데이터 유출 방지를 위해 저장되는 데이터 양을 최소화하고, VC는 암호화된 형태로 필요한 기간 동안만 저장해야 한다.
-   **상관 관계 방지**: VC에 인코딩된 고유 값(클레임, 식별자, 서명 등)을 통한 사용자 추적을 방지하기 위해 고유 VC 사용, 비상관 관계 암호화 스키마 사용, 추적 가능한 값 폐기 등을 적용해야 한다.
-   **민감 정보 노출 방지**: 인증 요청 시 민감한 정보를 포함하지 않아야 하며, Wallet 증명 주체는 특정 인스턴스가 아닌 Wallet 유형을 식별하는 값이어야 한다.
-   **발급자 및 Wallet 식별 정보 보호**: 발급자 식별 정보(URL, 인증서 등)를 통한 최종 사용자 정보 유추를 방지하고, Wallet 식별 정보 유출 방지를 위해 사용자 상호 작용 또는 발급자 신뢰 설정을 요구해야 한다.
-   **신뢰할 수 없는 Wallet 처리**: Wallet이 민감한 정보를 적절히 처리하도록 발급자는 Wallet을 적절히 인증하고 신뢰할 수 있는 엔터티인지 확인해야 한다.

<br>

### 4.2 OID4VP

OID4VP(OpenID for Verifiable Presentation)는 OpenID 프로토콜을 기반으로 사용자가 보유한 Verifiable Credential을 안전하게 제출(Presentation)할 수 있도록 정의한 규약이다.  
Wallet은 사용자의 동의를 받아 Verifier가 요청한 Verifiable Presentation을 생성하고 제출하며, QR 코드 등을 통해 Cross Device 등 여러 시나리오를 지원한다.  
이 표준은 OpenID Connect의 요청 객체(request object), nonce, JWT 등을 차용하여 보안성과 상호운용성을 확보한다.

#### 4.2.1 OID4VP 개요

OID4VP는 VP 제출 과정에서 OpenID Connect의 일부 개념을 활용하여 상호운용성이 보장된 보안 모델을 구성한다. OID4VP는 OpenID Connect의 구조적 요소들을 활용하지만, OAuth 2.0의 인증/인가 플로우와는 본질적으로 독립적이다.

- **Wallet**: Verifiable Credential을 보유하고, Verifier의 요청에 따라 Presentation을 생성하는 주체로서 OpenID의 Relying Party 또는 RP Client로 간주될 수 있음  
- **사용자 (Holder / End-User)**: 자신의 VC 사용에 대한 동의를 제공하며, VP 생성 시 인증 또는 승인 절차에 참여하는 Resource Owner에 해당  
- **Verifier**: VP를 요청하고 검증하는 주체로, OpenID Connect에서 Request Object를 생성하는 Entity 역할을 수행  
- **OIDC 구성 요소 활용**: OAuth 2.0의 Authorization Code Flow는 사용되지 않으며, 대신 `request_uri`, `request` 파라미터, `nonce`, `id_token` 등의 OIDC 요소가 적용됨

#### 4.2.2 Cross Device Flow vs. Same Device Flow

OID4VP는 두 가지 주요 제출 흐름(Credential Presentation Flow)을 지원하여 다양한 사용자 환경과 디바이스 상황에 대응한다.

- **Cross Device Flow**:  
  사용자가 Verifier의 요청을 `다른 디바이스(Wallet 앱이 설치된 모바일 기기 등)`를 통해 처리하는 방식이다.  
  Verifier는 Authorization Request를 QR 코드 등의 형태로 사용자에게 제공하며, 사용자는 이를 모바일 Wallet으로 스캔 등을 하여 VP를 생성하고 제출한다.  
  이 방식은 보안성과 사용자 편의성을 모두 고려하여, 웹 브라우저 기반 서비스와 모바일 지갑 간 상호작용이 가능하도록 설계되어 있다.

![Cross_Device Flow](./images/oid4vp_cross_device_flow.svg)

- **Same Device Flow**:  
  사용자가 Verifier와 Wallet을 `동일한 디바이스(예: 모바일 브라우저 + Wallet 앱 또는 통합 앱)`에서 사용하는 방식이다.  
  일반적으로 앱 간 전환(deep-linking)이나 인앱 웹뷰 등을 통해 Authorization Request를 전달하고, 사용자는 인증 및 동의 후 직접 Wallet에서 VP를 생성하여 Verifier에 제출한다.  
  이 방식은 Cross Device에 비해 UX 흐름이 간단하며, 관련된 환경 구성이 가능하다면 사용자 경험이 향상될 수 있도록 설계되어 있다.

![Same_Device Flow](./images/oid4vp_same_device_flow.svg)

#### 4.2.3 OID4VP Redirect 기반 요청-응답 구조

OID4VP는 Verifier가 사용자에게 요청한 Verifiable Credential(VC)을, Wallet을 통해 Verifiable Presentation(VP)으로 제출받는 구조를 정의한다. 이 과정은 OAuth 2.0 및 OpenID Connect의 redirect 구조를 활용하며, 사용자는 요청 URI를 통해 Wallet을 실행하고, VP를 생성하여 Verifier에 제출한다.

##### 4.2.3.1 OID4VCI와 다르게 OID4VP에 고정된 endpoint 개념이 없는 이유

OID4VCI는 Credential을 발급하는 Issuer가 고정된 서비스 주체이므로, `/credential_offer` 등과 같은 고정된 endpoint를 사용해 클라이언트가 일관되게 접근할 수 있도록 설계된다. 반면, OID4VP에서의 Verifier는 인증 요청을 동적으로 생성하는 주체이며, 상황에 따라 Presentation Definition, response\_uri 등을 바꾸는 유연성이 필요하다. 이로 인해 OID4VP에서는 별도의 고정 endpoint 개념 없이 `request_uri`를 통해 요청 정보를 전달하고, 이를 Wallet이 해석해 응답하는 방식으로 동작한다.

즉, Issuer(VC 발급자)는 고정된 서비스를 통해 여러 Wallet이 접근하길 기대하기 때문에 stable endpoint가 적합한 반면, Verifier는 매 요청마다 사용자에 따라 커스터마이즈된 presentation 요청을 생성하기 때문에 매번 동적으로 request\_uri만 제공하는 구조가 적절하다. 따라서 OID4VCI는 안정적인 엔드포인트 설계가 핵심이고, OID4VP는 유연한 요청 설계가 핵심이다.

| 구분          | OID4VCI                   | OID4VP               |
| ----------- | ------------------------- | -------------------- |
| 주체          | Issuer                    | Verifier             |
| 목적          | VC 발급                     | VP 제출                |
| 고정 Endpoint | 있음 (/credential\_offer 등)   | 없음 (동적 request\_uri) |
| 요청 구조       | OAuth2 Authorization Flow | redirect 기반 구조       |
| 설계 특징       | 안정적인 엔드포인트 설계 | 유연한 요청 설계      |

##### 4.2.3.2 OID4VP redirect 구성요소 설명

| 파라미터            | 설명                                    | 필수 여부 |
| --------------- | ------------------------------------- | ----- |
| `client_id`     | Wallet이 응답을 보낼 대상 URI 또는 Verifier 식별자 | 필수    |
| `request_uri`   | 요청 내용이 담긴 JWT 또는 JSON의 URI            | 필수    |
| `response_type` | 반환받을 토큰의 유형 (예: `vp_token`)           | 필수    |
| `response_mode` | 응답 방식 (`fragment`, `direct_post`)     | 선택    |
| `state`         | CSRF 방지 및 요청 추적을 위한 값                 | 권장    |
| `nonce`         | Presentation 재사용 방지를 위한 식별자           | 권장    |

**예시 redirect URI:**

```
openid-vp://?client_id=https%3A%2F%2Fverifier.example.com%2Fcb
&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest.jwt
&response_type=vp_token
&response_mode=direct_post
&state=xyz123
&nonce=abc456
```

##### 4.2.3.3 request_uri를 호출할 시 응답할 uri를 얻는 예제

request\_uri는 Verifier가 사전에 생성한 Presentation 요청이 포함된 리소스이다. Wallet은 이 URI를 호출하여, 요청의 상세 내용과 응답할 URI를 확인한다. 일반적으로는 `response_uri`가 명시되지만, 생략된 경우에는 `client_id`를 응답용 URI로 사용한다. 즉, 두 값 중 우선순위는 `response_uri`가 있으면 우선 사용되고, 없을 경우 fallback으로 `client_id`가 사용된다.

`response_uri`는 명시적으로 응답을 받을 URL을 지정하는 값이며, `client_id`는 기본적으로 Wallet에 자신을 식별시키기 위한 값이다. 하지만 `response_uri`가 없는 경우 fallback으로 `client_id`를 사용할 수 있도록 되어 있다. 개발 시에는 `response_uri`를 명확히 지정하는 것이 바람직하다.

**요청:**

```
GET https://verifier.example.com/request.jwt
```

**응답 예시:**

```json
{
  "client_id": "https://verifier.example.com/callback",
  "presentation_definition": {
    "id": "student_vc_request",
    "input_descriptors": [...]
  },
  "response_mode": "direct_post",
  "response_uri": "https://verifier.example.com/submit"
}
```

Wallet은 위 정보를 참고하여 VP를 생성한 후 `response_uri`가 있다면 해당 URI로, 없다면 `client_id`를 응답 주소로 사용한다.

#### 4.2.4 OID4VP Verifier Metadata

Verifier Metadata는 Verifier가 자신의 서비스 정보를 Wallet에 제공하기 위한 구조화된 정보 집합이다. Issuer가 Credential Issuance 시 .well-known/openid-credential-issuer를 통해 메타데이터를 제공하는 것과 유사하게, Verifier도 자신의 Presentation 요청 형식, 지원하는 Credential 형식 등을 기술할 수 있다.

##### 4.2.4.1 OID4VCI의 Issuer의 .well-known처럼 OID4VP에서는 고정 경로로 획득되지 않는 이유

OID4VCI의 Issuer는 안정적인 서비스 제공 주체로서, 고정된 메타데이터 경로를 통해 여러 Wallet이 접근하기를 기대한다. 하지만 Verifier는 동적으로 생성된 Presentation 요청(request\_uri)을 통해 각각의 요청에 맞는 메타데이터를 Wallet에 전달하기 때문에, 고정된 경로가 필요하지 않다. 즉, request\_uri 자체에 필요한 메타데이터를 포함하거나, JWT 내부에 inline으로 전달하는 구조로 충분하다.

##### 4.2.4.2 OID4VP Verifier Metadata 획득 방식

OID4VP에서는 Verifier가 정적인 `.well-known` 메타데이터를 제공하기보다는, **각 요청마다 메타데이터를 동적으로 포함하거나 외부 링크로 전달**하는 방식을 따른다. 다음과 같은 방식이 사용된다:

| 방식                 | 설명                                                                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **JWT에 inline 포함** | `request_uri`를 통해 전달된 JWT 내부에 Verifier Metadata가 직접 포함되어 전달된다. Wallet은 이 JWT를 파싱하여 요청된 Presentation 정보와 요구사항을 확인할 수 있다.                     |
| **외부 JSON URI 참조** | JWT 내부에 `presentation_definition_uri` 같은 키로 외부 JSON 파일의 URL을 명시하고, Wallet이 해당 JSON을 가져와 해석하도록 구성할 수 있다. Presentation 정의를 재사용하거나 유지보수에 유리하다. |

이러한 구조는 Verifier가 매 요청마다 다른 Presentation 요구사항을 전달할 수 있도록 하며, Wallet은 메타데이터를 통해 정확한 요청 조건을 파악한 후 Verifiable Presentation을 생성하게 된다.

##### 4.2.4.3 데이터 예제 및 구성요소 설명

아래는 Verifier Metadata의 예시 JSON과 그 구성요소 설명이다.

```json
{
  "client_id": "https://verifier.example.com",
  "vp_formats": {
    "jwt_vp": {
      "alg": ["ES256"]
    }
  },
  "presentation_definition": {
    "id": "age_verification",
    "input_descriptors": [
      {
        "id": "age_over_18",
        "format": {
          "jwt_vc": {
            "alg": ["ES256"]
          }
        },
        "constraints": {
          "limit_disclosure": "required"
        }
      }
    ]
  }
}
```

| 항목                               | 설명                                                                               |
| -------------------------------- | -------------------------------------------------------------------------------- |
| `client_id`                      | Verifier의 고유 식별자로, 요청 응답 시 참조되는 URI 역할도 수행한다. 일반적으로 OIDC의 `client_id`와 동일한 개념이다. |
| `vp_formats`                     | Verifiable Presentation의 포맷 및 서명 알고리즘 정보를 정의한다. 예: `jwt_vp`, `ldp_vp` 등.         |
| `presentation_definition`        | Verifier가 요청하는 VC의 유형, 형식, 조건 등을 명시한다. Presentation Exchange 규격 기반 구조다.          |
| └ `input_descriptors`            | 사용자가 제출해야 하는 Credential 요구사항 리스트로, 각 항목마다 별도의 조건을 설정할 수 있다.                      |
| └ `format`                       | 해당 input descriptor에서 허용하는 Credential의 포맷과 알고리즘을 정의한다.                           |
| └ `constraints.limit_disclosure` | 최소한의 정보만 제출하도록 요구하는 조건으로, selective disclosure 또는 ZKP와 관련된다.                     |

이러한 메타데이터 구조를 통해 Verifier는 구체적인 요청 조건을 명확히 기술할 수 있으며, Wallet은 이에 맞는 VC를 자동으로 선택하여 안전하게 Presentation을 생성한다.

#### 4.2.5 OID4VP DCQL

DCQL(Data Credential Query Language)은 Verifier가 Wallet에 요청하고자 하는 Credential의 내용을 보다 명확하고 직관적으로 표현할 수 있도록 설계된 JSON 기반 쿼리 언어이다. Credential의 구조를 그대로 반영하여, 개발자가 쉽게 읽고 작성할 수 있는 장점이 있다.

##### 4.2.5.1 데이터 예제 및 구성요소 설명 (Student ID VC와 mDL VC 중심)

아래는 DCQL을 사용하여 StudentIDCredential과 mDL Credential을 요청하는 예시이다. 실제 Credential에서 사용하는 필드 이름과 구조를 그대로 사용하여 조건을 명시하고 있다.

```json
{
  "type": "QueryByExample",
  "credentialQuery": [
    {
      "requiredCredential": {
        "type": ["StudentIDCredential"],
        "credentialSubject": {
          "enrollmentStatus": "active",
          "student": true,
          "school": {
            "name": "OpenID University"
          }
        },
        "issuer": "did:web:university.example.edu"
      }
    },
    {
      "requiredCredential": {
        "type": ["mDL"],
        "credentialSubject": {
          "birthDate": {
            "$lt": "2005-01-01"
          },
          "documentNumber": {
            "$exists": true
          }
        }
      }
    }
  ]
}
```

| 필드                                         | 설명                                            |
| ------------------------------------------ | --------------------------------------------- |
| `type`                                     | 쿼리 유형 지정. DCQL에서는 일반적으로 `"QueryByExample"` 사용 |
| `credentialQuery`                          | 요구하는 Credential 조건 목록                         |
| `requiredCredential.type`                  | 원하는 Credential의 타입. VC 내의 `type` 필드 기준        |
| `credentialSubject`                        | 제출받고자 하는 VC의 본문 데이터 구조 기준으로 claim 조건 명시       |
| `credentialSubject.enrollmentStatus`       | 현재 재학 상태 여부 (예: `"active"`)                   |
| `credentialSubject.birthDate.$lt`          | 생년월일이 2005년 1월 1일 이전이어야 함                     |
| `credentialSubject.documentNumber.$exists` | 해당 필드가 존재해야 함                                 |
| `issuer`                                   | 신뢰 가능한 Credential 발급자의 DID 명시                 |

DCQL의 쿼리는 실제 제출받고자 하는 VC의 구조와 매우 유사하게 작성되며, 별도의 경로 표기나 필터 구문을 외울 필요 없이 직관적으로 이해하고 활용할 수 있다.

##### 4.2.5.2 동일 요청의 Presentation Exchange v1 표현 비교 예제

**DCQL 예제 요약:**

* **StudentIDCredential**

  * `enrollmentStatus`가 `"active"`
  * `student`가 `true`
  * `school.name`이 `"OpenID University"`
  * `issuer`는 `"did:web:university.example.edu"`

* **mDL (모바일 운전면허증)**

  * `birthDate`가 `"2005-01-01"` 이전
  * `documentNumber` 필드가 존재해야 함

**DCQL 기반 요청 예시:**

```json
{
  "type": "QueryByExample",
  "credentialQuery": [
    {
      "requiredCredential": {
        "type": ["StudentIDCredential"],
        "credentialSubject": {
          "enrollmentStatus": "active",
          "student": true,
          "school": {
            "name": "OpenID University"
          }
        },
        "issuer": "did:web:university.example.edu"
      }
    },
    {
      "requiredCredential": {
        "type": ["mDL"],
        "credentialSubject": {
          "birthDate": {
            "$lt": "2005-01-01"
          },
          "documentNumber": {
            "$exists": true
          }
        }
      }
    }
  ]
}
```

**동일 요청의 Presentation Exchange v1 표현 예시:**

```json
{
  "presentation_definition": {
    "id": "vc_request",
    "input_descriptors": [
      {
        "id": "student_id_credential",
        "name": "Student ID Credential",
        "schema": [
          {
            "uri": "https://example.org/schema/StudentIDCredential"
          }
        ],
        "constraints": {
          "fields": [
            {
              "path": ["$.credentialSubject.enrollmentStatus"],
              "filter": {
                "type": "string",
                "const": "active"
              }
            },
            {
              "path": ["$.credentialSubject.student"],
              "filter": {
                "type": "boolean",
                "const": true
              }
            },
            {
              "path": ["$.credentialSubject.school.name"],
              "filter": {
                "type": "string",
                "const": "OpenID University"
              }
            }
          ]
        }
      },
      {
        "id": "mobile_dl",
        "name": "Mobile Driving License",
        "schema": [
          {
            "uri": "https://example.org/schema/mDL"
          }
        ],
        "constraints": {
          "fields": [
            {
              "path": ["$.credentialSubject.birthDate"],
              "filter": {
                "type": "string",
                "format": "date",
                "formatMaximum": "2005-01-01"
              }
            },
            {
              "path": ["$.credentialSubject.documentNumber"],
              "filter": {
                "type": "string"
              }
            }
          ]
        }
      }
    ]
  }
}
```

**구성요소 비교:**

| 항목         | DCQL 예제                                   | PEx v1 예제                                                      |
| ---------- | ----------------------------------------- | -------------------------------------------------------------- |
| VC Type 지정 | `type: ["StudentIDCredential"]`           | `schema.uri: "https://example.org/schema/StudentIDCredential"` |
| 필드 조건 표현   | Credential 구조 그대로 (`credentialSubject.*`) | JSONPath 기반 (`$.credentialSubject.*`)                          |
| 값 조건       | 직접 값 지정 (예: `"active"`, `true`)           | `filter.const` 등 필터 명령어를 통해 값 지정                               |
| 필드 존재 조건   | `$exists: true`로 명시                       | `filter.type` 명시 또는 암시적 표현 (불명확)                               |
| 날짜 조건 표현   | `$lt: "2005-01-01"`                       | `formatMaximum: "2005-01-01"` 사용                               |
| 구조 직관성     | 높음 (Credential 구조와 동일하게 기술됨)              | 낮음 (구조와 조건이 분리됨)                                               |

* DCQL은 Credential 구조를 그대로 활용하기 때문에 claim 단위 필터링이 직관적이다.
* 개발자는 VC를 다루듯이 쿼리를 작성할 수 있어 학습 부담이 적다.
* 반면, PEx v1은 JSONPath와 필터 문법의 조합을 요구하며, 오류 발생 가능성이 높고 유지보수가 어렵다.

#### 4.2.6 OID4VP VP Token

VP Token은 Verifiable Presentation을 JWT 형식으로 인코딩한 토큰이며, Verifier에게 안전하고 표준화된 방식으로 VC(Verifiable Credential)를 제출할 수 있도록 한다. OID4VP에서는 JWT 기반의 일반 VP Token뿐만 아니라, OpenID Connect ID Token에 VP를 포함하는 방식(ID Token 기반)도 지원한다.

##### 4.2.6.1 JWT 기반 VP Token 데이터 예제 및 구성요소 설명

JWT 기반 VP Token은 Presentation을 JWT의 payload로 인코딩한 구조를 가진다. 일반적으로 `vp` 클레임을 사용하여 Presentation을 담고, `nonce`와 `aud` 값을 통해 보안성을 확보한다.

**예제:**

```json
{
  "iss": "did:example:wallet",
  "aud": "https://verifier.example.com",
  "nonce": "n-0S6_WzA2Mj",
  "exp": 1686403200,
  "iat": 1686403100,
  "vp": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "verifiableCredential": [
      "eyJhbGciOiJFZERTQSIsInR..."
    ]
  }
}
```

**주요 구성요소 설명:**

| 항목           | 설명                                              |
| ------------ | ----------------------------------------------- |
| `iss`        | Wallet의 DID 또는 발급 주체 식별자                        |
| `aud`        | 요청을 보낸 Verifier의 식별자                            |
| `nonce`      | 요청-응답의 연결성을 위한 임의값                              |
| `vp`         | Verifiable Presentation 데이터 (JWT 또는 JSON-LD 형태) |
| `exp`, `iat` | 토큰 유효기간 정보                                      |

##### 4.2.6.2 ID Token 기반의 VP Token 데이터 예제 및 구성요소 설명

OID4VP는 ID Token을 확장하여 VP를 포함하는 방식도 허용한다. 이 방식은 특히 기존 OpenID Connect 인프라와의 통합을 고려한 설계이다.

**예제:**

```json
{
  "iss": "https://wallet.example.org",
  "sub": "did:example:123456789",
  "aud": "https://verifier.example.com",
  "exp": 1686403200,
  "iat": 1686403100,
  "nonce": "n-0S6_WzA2Mj",
  "vp_token": {
    "presentation_submission": {
      "id": "123456",
      "definition_id": "cred-def-456",
      "descriptor_map": [
        {
          "id": "email_cred",
          "format": "jwt_vc",
          "path": "$.vp.verifiableCredential[0]"
        }
      ]
    },
    "vp": {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiablePresentation"],
      "verifiableCredential": [
        "eyJhbGciOiJFZERTQSIsInR..."
      ]
    }
  }
}
```

**주요 구성요소 설명:**

| 항목                        | 설명                                          |
| ------------------------- | ------------------------------------------- |
| `sub`                     | Wallet 사용자의 식별자 (예: DID)                    |
| `vp_token`               | VP Token을 포함하는 확장 클레임                       |
| `presentation_submission` | 제출된 VC에 대한 매핑 정보 (Presentation Exchange 기반) |
| `vp`                      | 제출된 Verifiable Presentation                 |

##### 4.2.6.3 일반 VP Token과 ID Token 기반 VP Token 비교

| 구분       | 일반 VP Token      | ID Token 기반 VP Token             |
| -------- | ---------------- | -------------------------------- |
| 구조       | JWT 자체가 VP Token | ID Token의 확장 필드에 VP 포함           |
| OIDC 호환성 | 낮음               | 높음 (SIOPv2 호환 가능)           |
| 클레임 위치   | 최상위에 `vp` 클레임    | `vp_token` 확장 클레임 |
| 사용 목적    | VP 제출 전용         | 로그인 및 VP 제출 통합                   |

#### 4.2.7 고려사항

OID4VP(OpenID for Verifiable Presentation)를 구현하거나 운영할 때는 보안, 구현, 개인정보 보호 측면에서의 다양한 고려사항을 충실히 검토해야 한다. OID4VP는 Presentation 요청, 사용자 인증, Cross Device 흐름 등 복합적인 요소를 포함하고 있어 다음과 같은 항목들이 중요하다.

##### 4.2.7.1 보안 고려사항 (Security Considerations)

* **Nonce 및 aud 사용**: 요청의 위변조 방지를 위해 요청 객체에 포함된 `nonce`, `aud` 값은 필수적으로 검증해야 하며, 재사용 공격 방지 목적에 활용된다.
* **요청 객체(request object)의 무결성**: JWT 서명된 요청 객체는 Verifier가 서명해야 하며, Wallet은 요청의 서명을 검증하고 신뢰할 수 있는 발신자인지 확인해야 한다.
* **Presentation 서명 검증**: Verifiable Presentation 내 VC의 서명뿐 아니라 Presentation 자체의 서명도 검증하여 위변조를 방지해야 한다.
* **Cross Device 공격 대응**: QR 기반 요청 시 중간자 공격 방지를 위한 endpoint URL 무결성 확인, secure channel 활용 등이 필요하다.

##### 4.2.7.2 구현 고려사항 (Implementation Considerations)

* **동적 요청 처리**: OID4VP는 요청 객체에 Verifier의 요구사항이 포함되므로 Wallet은 동적으로 해당 요청을 파싱하고 응답할 수 있어야 한다.
* **동일 기기 / 교차 기기 흐름 대응**: 다양한 UX 시나리오(Cross Device, Same Device)에 대응할 수 있도록, 각각에 맞는 URI 스킴, 딥링크 처리, QR 스캔 로직 등이 필요하다.
* **Presentation Submission 처리**: Verifier가 요청한 Descriptor Map에 따라 적절한 VC를 대응하여 제출하는 Presentation Exchange 구조를 구현해야 한다.
* **메타데이터 처리**: Verifier 메타데이터를 통해 요청 형식, 요청 방식, 서명자 정보를 사전에 합의하고 관리할 수 있도록 해야 한다.

##### 4.2.7.3 개인정보 보호 고려사항 (Privacy Considerations)

* **최소 정보 제출 원칙**: Verifier가 요청한 claim만 포함되도록 Presentation을 구성해야 하며, Wallet은 이에 대한 UI/UX를 제공해야 한다.
* **ZKP 및 Selective Disclosure**: 민감한 정보는 Zero-Knowledge Proof, BBS+ 등 프라이버시 강화 기술을 적용하여 제출하는 것이 바람직하다.
* **사용자 동의 기반 처리**: 사용자가 어떤 VC와 claim을 어떤 Verifier에게 제공하는지 명확히 인식하고 동의할 수 있도록 안내 및 시각화가 필요하다.
* **전송 후 저장 정책**: Verifier 측에서 수신한 VC/VP 데이터를 장기 보관하거나 로그에 저장할 경우, 법적·윤리적 문제가 발생할 수 있으므로 명확한 보관 정책이 수립되어야 한다.

### 4.3 SIOPv2

#### 4.3.1 개요 및 역할

**SIOPv2 (Self-Issued OpenID Provider v2)** 는 사용자가 자기 자신을 OpenID Provider로 삼아, **중앙 ID 제공자 없이 스스로 인증을 수행하는 분산 신원 인증 모델** 이다.
nnn1
- 기존의 Google, Facebook 같은 중앙화된 IDP 구조를 대체
- 사용자가 직접 **ID Token을 생성**하고, 이를 제시함으로써 **자기주권형 신원(Self-Sovereign Identity, SSI)** 실현
- OpenID Connect(OIDC)의 흐름을 그대로 따르므로 기존 생태계와의 호환성 확보

**핵심 포인트:**
- 사용자가 직접 서명한 JWT ID Token(DIDAuth와 유사)을 발급
- DID 기반으로 사용자를 식별 사용자가 계속해서 나머지 내용을 작성해달라고 요청했습니다. 이전 내용을 계속해서 작성하겠습니다.

및 검증, OIDC 확장 구조
- VC 발급 요청(OID4VCI) 또는 VC 제시(OID4VP) 시에 인증 주체로 사용됨

#### 4.3.2 OID4VCI에서의 Client Authentication 방식으로 사용

OID4VCI에서 사용자는 Credential Issuer에게 VC 발급을 요청한다.  
이때 Issuer는 요청자의 신원을 확인해야 하며, **Client Authentication** 방식으로 **SIOP 기반 ID Token** (사용자의 식별자 기능)이 활용된다. 

##### 흐름 요약:
1. 사용자가 월렛을 통해 VC 발급 요청
2. 월렛은 **SIOP 방식으로 ID Token 생성**
3. Credential Issuer는 해당 ID Token을 검증하여 사용자 식별 및 인증 수행

> 기존 `client_secret`, `client_assertion` 방식 대신 사용자가 **직접 서명한 ID Token**을 사용하는 방식

#### 4.3.3 OID4VP에서의 Subject 인증 방식으로 사용

OID4VP는 사용자가 VC를 제시할 때, Verifier가 **누가 제시했는가** 를 검증해야 한다.
이때 SIOPv2는 **VC의 제시 주체(Subject)** 인증 수단으로 사용된다.

##### 간략 인증 흐름:
1. Verifier가 Presentation Request 전송
2. Wallet이 **SIOPv2 방식의 ID Token** 생성
3. VP와 함께 Verifier에게 전달
4. Verifier는 ID Token의 서명을 확인하고, DID를 통해 소유자 식별

##### 서비스 이용시 인증 흐름:
<img src="./images/siop_service_flow.png" alt="SIOP 시퀀스" width="70%">

<img src="./images/siop_detail_seq.svg" alt="SIOP 시퀀스" width="100%">

#### 4.3.4 ID Token 발급 구조 (JWT + DID)

SIOPv2에서 발급하는 ID Token은 다음과 같은 **JWT 구조**를 가진다:

##### JWT 구성:

###### Header
```json
{
  "alg": "ES256K",
  "typ": "JWT",
  "kid": "did:wallet:123#key-1"
}
```

###### Payload (예시)
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
  "vp_token": {VC발급 시, VP제출 시 데이터 포함 가능}  // VP 제출시 IDToken 활용한다면 VP데이터 포함
}
```

###### Signature
- DID Document에 등록된 wallet의 개인키로 서명
- 공개키는 DID를 통해 검증 가능

#### 4.3.5 SIOP 기반 Wallet의 검증 흐름

월렛이 인증 주체로 동작할 때, Verifier 또는 Credential Issuer는 월렛이 제시하는 **ID Token의 진위**와 **서명자 식별자(DID)** 를 검증한다.

##### 시퀀스 다이어그램 (OID4VP 기준)

![SIOP 시퀀스](./images/siop_simple_seq.svg)

##### 설명 요약:

1. **Wallet**은 DID를 기반으로 JWT 서명
2. **Verifier**는 해당 DID를 resolve 하여 공개키 확보
3. **JWT의 서명과 Claim 유효성**을 검증하여 사용자의 소유권 확인

##### 정리

| 항목 | 설명 |
|------|------|
| **SIOPv2** | 사용자가 직접 인증 주체가 되는 분산 ID 방식 |
| **OID4VCI** | VC 발급 시 월렛이 ID Token을 이용해 자신을 인증 |
| **OID4VP** | VC 제시 시 월렛이 제시자의 신원을 ID Token으로 증명 |
| **ID Token 구조** | JWT 형식, DID 기반 발급자, 서명 포함 |
| **검증 흐름** | DID → 공개키 → JWT 서명 및 Claim 검증 |

**SIOPv2는 Self-Sovereign Identity 실현을 위한 핵심 구성요소로, 신뢰 가능한 자기주권형 인증을 구현함.**

## 5. OID4VC 적용 전략
### 5.1 개요
OID4VC 적용 전략은 위의 OID4VC 분석 결과를 바탕으로, 기존 DID 시스템에 OID4VC 표준(OID4VCI, OID4VP, SIOPv2)을 적용하기 위한 구체적인 실행 방안과 전략을 기술한다. 목표로서 EUDI Wallet 등 글로벌 디지털 지갑과의 상호운용성을 확보하고, 개방형 표준을 준수하여 시스템을 고도화하는 등의 과제를 지닌다.

### 5.2 목표 시스템 아키텍처
OID4VC 표준을 적용하기 위해 기존 시스템 구성에 **Authorization Server (AS)**를 추가하고, 각 컴포넌트의 역할을 재정의해야 한다.
- **Authorization Server (신규 개발)**: OAuth 2.0 기반의 인가/인증을 전담하는 서버. VC 발급 시 사용자의 동의를 얻고 Access Token을 발급하는 핵심 역할을 수행한다.
- **did-issuer-server (기능 변경)**: OID4VCI 표준에 따라 VC를 발급하는 **Resource Server** 역할을 수행한다. AS가 발급한 Access Token을 검증하여 VC를 발급한다.
- **did-verifier-server (기능 변경)**: OID4VP 표준에 따라 VP를 요청하고 검증하는 **Verifier** 역할을 수행한다.
- **did-ca-aos / did-client-sdk-aos / did-ca-ios / did-client-sdk-ios (기능 변경)**: 사용자의 Wallet으로서 OID4VCI의 **Client**, OID4VP의 **Prover**, SIOPv2의 **Self-Issued OpenID Provider** 역할을 모두 수행한다.
- **did-ta-server (역할 유지)**: DID 발급 및 신뢰 검증을 위한 인프라로서, DID Resolution 과정에서 기존 역할을 그대로 유지한다. 단, **VC 발급 시 TAS를 경유하는 부분**은 프로토콜 변경이 필요하다.

### 5.3 신규 개발 요구사항

#### 5.3.1 Authorization Server (AS) 구현

기존 시스템에는 OAuth 2.0 표준을 지원하는 독립적인 Authorization Server가 부재하므로 신규 개발이 필수적이다.

- **주요 기능:**
    - **OAuth 2.0 표준 엔드포인트 구현:**
        - `/authorize`: 사용자의 인증 및 동의를 처리하고 Authorization Code를 발급함.
        - `/token`: Authorization Code 또는 Pre-authorized Code를 Access Token, Refresh Token으로 교환함.
    - **클라이언트 관리:** Wallet 등 OAuth 2.0 클라이언트의 등록 및 관리 기능.
    - **사용자 인증:** VC 발급을 요청하는 사용자를 인증하는 기능 (ID/PW, 생체인증 등).
    - **토큰 관리:** Access Token 및 Refresh Token의 발급, 검증, 만료 정책 관리.
    - **PKCE 지원:** Authorization Code 탈취 공격을 방지하기 위한 PKCE(Proof Key for Code Exchange) 지원.

#### 5.3.2 기존 오픈소스 변경 요구사항

##### 5.3.2.1 `VC 발급 프로토콜에서` `TAS` 경유 → `Issuer 직접 접근` 혹은 `Proxy 서버 경유`로 분리
- **Issuer 직접 접근:** OID4VCI Issuer 엔드포인트 구현 주체가 TAS가 될 수 없으므로, Issuer 직접 접근으로 구조 변경 필수.
- **Proxy 서버 경유:** Issuer 직접 접근이 구조적으로 어려운 경우, Reverse Proxy 서버 등을 통한 Issuer 중개 가능.

##### 5.3.2.2 `did-issuer-server` → OID4VCI Issuer 역할로 변경

- **엔드포인트 구현:** OID4VCI 표준에 따라 다음 엔드포인트를 구현해야 함.
    - `/.well-known/openid-credential-issuer` (GET): Issuer의 정책과 기술 사양(지원하는 VC 종류, 엔드포인트 주소, 암호화 방식 등)을 담은 **Issuer Metadata**를 제공함.
    - `/credential_offer` (GET/POST): Wallet에 VC 발급 제안(Credential Offer)을 전달함.
    - `/credential` (POST): Wallet으로부터 Access Token과 `proof`가 포함된 VC 발급 요청을 받아 처리함.
    - (선택) `/nonce`, `/deferred_credential`, `/notification` 등 부가 엔드포인트 구현.
- **프로토콜 변경:**
    - **Access Token 검증:** VC 발급 요청 시 `Authorization` 헤더에 포함된 Access Token을 AS에 검증 요청하는 로직을 추가해야 함.
    - **VC 발급 흐름 지원:**
        - **Authorization Code Flow:** AS를 통한 사용자 인증/동의 후 발급하는 흐름을 지원함.
        - **Pre-authorized Code Flow:** 외부 채널을 통해 사전 인증된 `pre-authorized_code`를 이용해 즉시 토큰을 교환하고 VC를 발급하는 흐름을 지원함.
    - **Holder Binding:** VC 발급 요청의 `proof` 파라미터(JWT 형식)를 검증하여, VC가 정당한 소유자(Holder)에게 발급되는지 확인하는 로직을 구현해야 함.

##### 5.3.2.3 `did-verifier-server` → OID4VP Verifier 역할로 변경

- **프로토콜 변경:** 기존의 독자적인 VP 제출 프로토콜을 OID4VP 표준으로 대체함.
    - **Presentation Request 생성:**
        - `request_uri`를 동적으로 생성하여 Wallet에 전달하는 기능을 구현함. 이 `request_uri`는 JWT 형식의 요청 객체를 가리키며, 내부에 `presentation_definition`을 포함함.
        - **Presentation Definition** 또는 **DCQL**을 사용하여 요청할 VC의 조건(종류, 클레임, 발급자 등)을 명세하는 기능을 구현함.
    - **VP Token 수신 및 검증:**
        - Wallet이 제출한 `vp_token`(JWT 형식) 또는 ID Token에 포함된 VP를 수신하는 엔드포인트(`response_uri` 또는 `client_id`로 지정된 경로)를 구현함.
        - 수신된 VP Token의 서명, `nonce`, `aud` 등을 검증하고, 내부에 포함된 VP와 VC의 유효성을 검증하는 로직을 구현함.
    - **Cross/Same Device Flow 지원:** QR 코드 생성, Custom App Scheme을 통한 딥링킹 등 다양한 사용자 환경을 지원하기 위한 로직이 필요함.

##### 5.3.2.4 `did-ca-aos`, `did-ca-ios` (CA) + `did-client-sdk-aos`, `did-client-sdk-ios` (Wallet) → OID4VC/SIOPv2 Client 역할로 변경

- **OID4VCI 클라이언트 기능:**
    - Credential Offer(`credential_offer` 또는 `credential_offer_uri`)를 해석하고, Issuer Metadata를 조회하여 발급 절차를 시작하는 기능을 구현함.
    - `authorization_details` 또는 `scope`를 사용하여 AS에 인가 요청을 보내고, `redirect_uri`를 통해 Authorization Code를 수신함.
    - 획득한 Code를 AS의 Token Endpoint로 보내 Access Token을 발급받음.
    - VC에 Holder의 DID를 바인딩하기 위해 개인키로 서명한 `proof`(JWT 형식)를 생성하고, Access Token과 함께 Issuer의 Credential Endpoint로 전송하여 VC를 발급받음.
- **OID4VP 클라이언트 (Prover) 기능:**
    - Verifier가 제시한 `request_uri`를 해석하여 `presentation_definition`을 파악함.
    - `presentation_definition`의 요구사항과 일치하는 VC를 로컬 저장소에서 검색함.
    - 사용자의 동의를 얻어 VP를 생성하고, 이를 `vp_token`(JWT)으로 패키징함. 이때 Verifier가 요청한 `nonce`를 포함하여 서명함.
    - 생성된 `vp_token`을 Verifier가 지정한 `response_uri`로 전송함.
- **SIOPv2 Provider 기능:**
    - OID4VCI/OID4VP 과정에서 신원 인증이 필요할 때, 자신의 DID를 `iss`와 `sub`으로 하는 **ID Token**을 생성하고 개인키로 서명하는 기능을 구현함.
    - 이 ID Token은 Client Authentication 또는 Subject 인증 용도로 사용됨.

#### 5.3.3 데이터 모델 및 프로토콜 표준화

- **JWT 전환:** 시스템 내에서 교환되는 모든 핵심 데이터(VC, VP, ID Token, `proof` 등)는 **JWT 형식**으로 통일함.
- **보안 표준 적용:** 데이터 보호를 위해 필요에 따라 **JWS(서명)**, **JWE(암호화)**, **JWK(키 표현)** 표준을 적용함.
- **기존 프로토콜 폐기:** OID4VC 표준 도입에 따라, 기존의 독자적인 VC/VP 교환 프로토콜은 점진적으로 폐기하고 OID4VCI/OID4VP로 완전히 대체함.

### 5.4 OID4VC 적용 전략

#### 5.4.1 점진적 적용 전략 (Phased Approach)

OID4VC 표준이 아직 `draft` 상태인 점을 고려하여, 안정성과 유연성을 모두 확보할 수 있는 점진적 적용 전략을 채택함.

- **1단계: 핵심 기반 구축 (MVP)**
    - **목표:** 가장 안정적이고 핵심적인 기능 우선 구현.
    - **내용:**
        1.  **Authorization Server 신규 개발:** OAuth 2.0의 핵심 기능(`authorization_code` grant type, token 발급)을 우선 구현함.
        2.  **SIOPv2 구현:** `did-client-sdk-aos`, `did-client-sdk-ios`에 DID 기반의 ID Token 생성 및 서명 기능을 구현하여, 기본적인 Self-Sovereign 인증 체계를 마련함.
        3.  **기존 프로토콜과 병행 운영:** OID4VC 기능 개발 중에도 기존 시스템의 안정적인 운영을 위해, 신규 OID4VC 엔드포인트와 기존 독자 프로토콜 엔드포인트를 병행하여 지원함. (예: `/api/v1/issue` 와 `/.well-known/openid-credential-issuer` 공존)

- **2단계: OID4VCI/OID4VP 핵심 플로우 적용**
    - **목표:** VC 발급 및 제출의 기본 플로우를 표준에 맞춰 구현.
    - **내용:**
        1.  **OID4VCI (Pre-authorized Code Flow 우선):** 비교적 구현이 간단하고 UX가 간결한 `Pre-authorized Code Flow`를 우선적으로 적용하여 VC 발급 기능을 구현함.
        2.  **OID4VP (Same Device Flow 우선):** `Same Device Flow`를 우선 구현하여 모바일 환경에서의 VP 제출 기능을 표준화함.
        3.  **표준 모니터링:** OpenID Foundation의 표준화 동향을 지속적으로 모니터링하고, `draft` 변경 사항을 빠르게 반영할 수 있는 유연한 구조로 설계함.

- **3단계: 전체 기능 확장 및 고도화**
    - **목표:** 전체 OID4VC 스펙을 지원하고, 글로벌 상호운용성을 확보함.
    - **내용:**
        1.  **전체 플로우 지원:** OID4VCI의 `Authorization Code Flow`와 OID4VP의 `Cross Device Flow`를 구현하여 모든 표준 플로우를 지원함.
        2.  **부가 기능 구현:** `deferred_credential`, `nonce` 엔드포인트, `DCQL` 지원 등 부가적인 스펙을 구현하여 기능을 고도화함.
        3.  **기존 프로토콜 전환:** OID4VC 기능이 안정화되면, 내부적으로 기존 프로토콜 사용을 점진적으로 중단(deprecate)하고 최종적으로 OID4VC로 완전히 전환함.

#### 5.4.2 상호운용성 확보 전략

글로벌 시스템(EUDI Wallet 등)과의 상호운용성은 OID4VC 도입의 핵심 목표 중 하나임. 이를 위해 다음 전략을 추진함.

- **1. OID4VC Conformance Profile 준수:**
    - EUDI Wallet Architecture and Reference Framework (ARF) 등 주요 글로벌 지갑들이 요구하는 **Conformance Profile**을 분석하고, 이를 충족하도록 시스템을 구현함.
    - 예를 들어, 지원해야 할 암호화 알고리즘(`alg`, `enc`), VC 포맷(`vc+sd-jwt`, `mso_mdoc`), Holder Binding 방식(`did`, `jwk`) 등을 사전에 정의하고 개발에 반영함.

- **2. 상호운용성 테스트 이벤트 참여:**
    - OpenID Foundation 등에서 주관하는 **상호운용성 테스트 이벤트(Interoperability Events)** 에 적극적으로 참여함.
    - 이를 통해 다른 구현체들과의 연동 테스트를 진행하고, 잠재적인 호환성 문제를 조기에 발견하고 해결함.

- **3. 유연한 메타데이터 관리:**
    - `did-issuer-server`의 Issuer Metadata (`/.well-known/openid-credential-issuer`)를 통해 우리 시스템이 지원하는 기술 스펙을 명확히 제공함.
    - Wallet(Client)은 이 메타데이터를 동적으로 해석하여 상호작용하므로, 향후 스펙 변경이나 기능 확장에 유연하게 대응할 수 있음.

- **4. 커뮤니티 및 표준화 활동 참여:**
    - OID4VC 관련 워킹그룹 및 커뮤니티 활동에 참여하여 최신 동향을 파악하고, 표준 제정 과정에 의견을 제시함으로써 우리 시스템에 유리한 방향으로 표준이 발전하도록 기여함.
    
### 5.5 결론

OID4VC 표준 적용은 단순한 프로토콜 변경을 넘어, 시스템 아키텍처 전반의 재설계가 필요한 중요한 과제임. 제안된 방안에 따라 신규 Authorization Server를 개발하고 기존 오픈소스들을 OID4VC 역할에 맞게 변경하여야 함.

또한 OID4VC 표준의 `draft` 상태와 글로벌 상호운용성의 중요성을 고려할 때, **점진적이고 유연한 적용 전략**이 필수적임. 제안된 단계별 로드맵과 상호운용성 확보 전략에 따라 시스템을 개발하고 발전시켜 나간다면, 변화하는 표준 환경에 성공적으로 적응하고 글로벌 경쟁력을 갖춘 DID 시스템을 구축할 수 있을 것임.


## 6. 부록

### 6.1 개요

본 부록에서는 OID4VC에서 사용되는 JSON 기반 보안 구조인 JWT, JWS, JWE, JWK에 대해 핵심 개념, 구조, 필드의 의미, 활용 방식 등을 간략히 정리함.

#### 6.1.1 JWT (JSON Web Token)

- **정의:** JSON으로 표현된 일련의 클레임(Claim)을 안전하게 전달하는, URL-safe 문자열
- **보안 적용:** JWS로 서명, JWE로 암호화 혹은 둘 다 가능. 즉, JWT 자체는 JWS/JWE 구조에 내포됨
- **용도:** 액세스 토큰, 인증/권한, VC, VP 등
- **주요필드:**

  | 필드                  | 설명                                 |
  | -------------------- | ---------------------------------- |
  | `header`             | 토큰 타입(`typ`), 서명 알고리즘(`alg`), 키 식별자(kid) 등 |
  | `payload`            | 클레임 정보(예: sub, name, iat, exp, VC 등 실제 데이터)           |
  | `signature`          | JWS 구조일 때 서명 값, JWE인 경우엔 없음(대신 암호화 됨)    |

- **형식:** header.payload.signature (JWS 기반)
  - **Header**
    ``` json
    { "alg":"HS256", "typ":"JWT" }

    Base64url 인코딩:
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    ```

  - **Payload**
    ``` json
    { "sub":"1234567890", "name":"John Doe", "admin":true }
    
    Base64url 인코딩:
    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9
    ```
  - **Signature:** HMAC-SHA256(header + "." + payload + secret)를 계산
    ```
    SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
    ```
  
  - **JWT (최종 문자열) 예시**
    ``` json
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.                                   //header
    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.   //Payload
    SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c                             //Signature
    ```
  
#### 6.1.2 JWS (JSON Web Signature)

- **정의**: JSON 객체에 대해 디지털 서명(MAC 포함)을 적용해 무결성과 출처 인증을 보장하는 구조
- **용도**: JWT 서명, VC/VP의 서명 보호
- **주요 필드(header 포함):**
  
   | 필드    | 설명                                 |
   | ----- | ---------------------------------- |
   | `alg` | 서명 알고리즘 (예: HS256, RS256, ES256)          |
   | `typ` | 토큰 타입 (일반적으로 `JWT` 사용)                     |
   | `kid` | 키 식별자 (JWK/JWKS와 매칭) |

- **형식**:
  - **Compact Serialization:**
  
    `Base64Url(Protected Header).Base64Url(Payload).Base64Url(Signature)`
    ```json
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.                                   // Header
    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.   // Payload
    SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c                             // Signture
    ```
    
  - **JSON Serialization:**  여러 서명, 헤더, recipient 지원
    ```json
    {
      "payload": "...", "protected": "...", "header": {...}, "signature": "..."
    }
    ```




#### 6.1.3 JWE (JSON Web Encryption)

- **정의**: JSON 데이터(혹은 임의 데이터)를 암호화하여 기밀성 및 무결성을 제공하는 구조
- **용도**: 암호화된 VC 전달, enc_vc 등
- **주요 필드(header 포함):**

  | 필드                | 설명                                |
  | ----------------- | --------------------------------- |
  | `protectedHeader` | 암호/키 관리 알고리즘(`alg`), 콘텐츠 암호화 알고리즘(`enc`), `kid` 등 포함 |
  | `encryptedKey`    | CEK(Content Encryption Key)의 수신자(recipient)별 암호 결과          |
  | `iv`              | 초기화 벡터 (Initialization Vector)    |
  | `ciphertext`      | 암호화된 데이터                         |
  | `tag`             | 무결성 검증을 위한 인증 태그 (AEAD에서 생성됨)     |

- **형식**:
  - **Compact Serialization:**
  
    `Base64Url(Protected Header).Base64Url(Encrypted Key).Base64Url(IV).Base64Url(Ciphertext).Base64Url(Tag)`
    ```json
    eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.   // ProtectedHeader
    OKOawDo13gRp2ojaHV7LFpPqKSan.                     // encryptedKey
    48V1_ALb6US04U3b.                                 // iv
    5eym8TW_c8SuK0ltJ3rpYIzOAmRf.                     // ciphertext
    XFBoMYUZodetZdvTiFvSkQ                            // tag
    ```

  - **JSON Serialization:** 복수 수신자(recipient), 추가 헤더 지원
    ```json
    {
      "protected": "...",
      "recipients": [
          { "header": {...}, "encrypted_key": "..." }
      ],
      "iv": "...", "ciphertext": "...", "tag": "..."
    }
    ```


#### 6.1.4 JWK (JSON Web Key)

- **정의:** 공개키, 비밀키 등 암호 키를 JSON 객체로 표현하는 데이터 구조 (단일/복수 모두 지원)
- **용도:** JWS 서명 검증, JWE 암호화/복호화 키 공유 등
 - **주요 필드:**
  
    | 필드       | 설명                           |
    | -------- | ---------------------------- |
    | `kty`    | 키 타입(예: EC, RSA) (필수)         |
    | `crv`    | 곡선 이름(EC 키일 경우, 예: P-256)        |
    | `x`, `y` | 공개키 좌표(EC 키일 경우)             |
    | `n`, `e` | 공개키 지수(RSA일 경우)              |
    | `use`    | 키 용도 (`sig`: 서명, `enc`: 암호화) |
    | `kid`    | 키 식별자 (JWS/JWE의 `kid`와 매칭)   |
- **형식:**
  - **단일 키:** JSON 객체
  - **키 집합:** `{ "keys": [ { ... }, ... ] }` 형식의 배열

- **예시 구조 (ECDSA 키):**
  ```json
  {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "use": "sig",
    "kid": "did:example:123#key-1"
  }
  ```

### 6.2 OID4VCI 기반 encVC 발급 과정 예시 (ECDH 예시)

**전제 조건**
```javascript
// Access Token이 발급된 상태
const accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
const credentialIssuerUrl = "https://issuer.example.com";
```

#### 6.2.1 Credential Issuer Metadata 조회

**API 호출: Wallet → Credential Issuer**
```http
GET /.well-known/openid-credential-issuer
Host: issuer.example.com
Accept: application/json
```

**응답 데이터**
```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/credential",
  "authorization_servers": ["https://auth.example.com"],
  "credential_configurations_supported": {
    "UniversityDegreeCredential": {
      "format": "jwt_vc_json",
      "credential_definition": {
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "context": ["https://www.w3.org/2018/credentials/v1"]
      },
      "credential_response_encryption": {
        "alg_values_supported": ["ECDH-ES", "ECDH-ES+A256KW"],
        "enc_values_supported": ["A128GCM", "A256GCM"],
        "encryption_required": true
      },
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256", "RS256"]
        }
      },
      "display": [
        {
          "name": "University Degree",
          "locale": "en-US",
          "logo": {
            "url": "https://issuer.example.com/logo.png"
          }
        }
      ]
    }
  }
}
```

#### 6.2.2 Wallet 서명용 임시 키 쌍 생성 및 JWK 변환

**Wallet 내부 처리**
```javascript
// secp256r1 키 쌍 생성
const keyPair = await crypto.subtle.generateKey(
  { name: "ECDH", namedCurve: "P-256" },
  true,
  ["deriveKey"]
);

// 공개키를 JWK로 변환
const publicJWK = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
const encryptionJWK = {
  ...publicJWK,
  alg: "ECDH-ES",
  use: "enc",
  kid: "wallet-enc-key-001"
};
```

**생성된 JWK 예시**
```json
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "ECDH-ES",
  "use": "enc",
  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", // JWK에서는 x, y가 필수
  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", // JWK에서는 x, y가 필수
  "mb_key": "zDnaekGZTbQBerwcehBSXLqkUBvy6L73p1CJ92BZyK3TF",  // multibase 인코딩
  "kid": "wallet-enc-key-001"
}
```

#### 6.2.3 Proof JWT 생성

**Wallet 내부 처리**
```javascript
// Proof JWT Header
const proofHeader = {
  "alg": "ES256",
  "typ": "openid4vci-proof+jwt",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "wallet_signing_public_key_x",
    "y": "wallet_signing_public_key_y",
    "mb_key": "mb_key"
  }
};

// Proof JWT Payload
const proofPayload = {
  "iss": "wallet-client-id",
  "aud": "https://issuer.example.com",
  "iat": 1641234567,
  "nonce": "server_provided_c_nonce"  // 이전 요청에서 받은 c_nonce
};

// JWT 서명 생성
const proofJWT = await signJWT(proofHeader, proofPayload, walletSigningPrivateKey);
```

**생성된 Proof JWT 예시**
```
eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiWEJfeWN0WkhOQUUzZVF2d0ktWDBybGQ1VUx6VVdVVDdHMkxJNUVzc2JVWSIsInkiOiJfMDJLeU9wVGIzZE9WN2pMdUt6ZzZWZklwVUQ0YlV1LUc1Um1nS0F5UmVvIn19.eyJpc3MiOiJ3YWxsZXQtY2xpZW50LWlkIiwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDEyMzQ1Njd9.signature
```

#### 6.2.4 Credential Request API 호출

**API 호출: Wallet → Credential Issuer**
```http
POST /credential
Host: issuer.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
Accept: application/jwt
```

**요청 데이터 (JWE 암호화 요청 포함)**
```json
{
  "format": "jwt_vc_json",
  "credential_definition": {
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "context": ["https://www.w3.org/2018/credentials/v1"]
  },
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiWEJfeWN0WkhOQUUzZVF2d0ktWDBybGQ1VUx6VVdVVDdHMkxJNUVzc2JVWSIsInkiOiJfMDJLeU9wVGIzZE9WN2pMdUt6ZzZWZklwVUQ0YlV1LUc1Um1nS0F5UmVvIn19.eyJpc3MiOiJ3YWxsZXQtY2xpZW50LWlkIiwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDEyMzQ1Njd9.signature"
  },
  "credential_response_encryption": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "alg": "ECDH-ES",
      "use": "enc",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "mb_key": "zDnaekGZTbQBerwcehBSXLqkUBvy6L73p1CJ92BZyK3TF",
      "kid": "wallet-enc-key-001"
    },
    "alg": "ECDH-ES",
    "enc": "A256GCM"
  }
}
```

#### 6.2.5 Credential Issuer 내부 처리

**서버 측 처리 로직**
```javascript
// 1. Access Token 검증
const userInfo = await validateAccessToken(request.headers.authorization);

// 2. Proof JWT 검증
const proofJWT = request.body.proof.jwt;
const proofPayload = await verifyProofJWT(proofJWT);

// 3. Credential 생성
const credential = await createCredential(userInfo, request.body.credential_definition);

// 4. 암호화가 요청된 경우 JWE 생성
if (request.body.credential_response_encryption) {
  // 4-1. 임시 키 쌍 생성
  const ephemeralKeyPair = await generateECDHKeyPair();
  
  // 4-2. ECDH 키 합의
  const sharedSecret = await performECDH(
    ephemeralKeyPair.privateKey,
    request.body.credential_response_encryption.jwk
  );
  
  // 4-3. CEK 파생
  const cek = await deriveContentEncryptionKey(sharedSecret, "A256GCM");
  
  // 4-4. JWE 생성
  const jwe = await createJWE(credentialResponse, cek, ephemeralKeyPair.publicKey);
  
  return jwe;
}
```

#### 6.2.6 JWE Credential Response

**HTTP 응답 전체 구조**

**HTTP Response Headers (원문)**
```http
HTTP/1.1 200 OK
Content-Type: application/jwt
Cache-Control: no-store
Pragma: no-cache
Content-Length: 1547
Date: Mon, 08 Jul 2024 12:34:56 GMT
Server: OID4VCI-Issuer/1.0
X-Request-ID: req-abc123
```

**HTTP Response Body (JWE 원문)**
```
eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImlUbTZ6Rk9hT0pxSGtYNHo4N0hXaUVkX0hLQnZxNmNWYTlCcUlkVjU1NE0iLCJ5IjoiOXoyX1VDVUN4eXVxVElqQlZoQ3RNUWFnYktOaUF0N2x5a0pBNklPNnc4cyJ9fQ..xVNrS3ZQaXZQYklNTA.encrypted_credential_data_base64url_encoded_very_long_string_here_representing_the_actual_credential_and_metadata_that_has_been_encrypted_using_aes_gcm_with_the_derived_cek_from_ecdh_key_agreement.YuJKcPwD1BvS5fN8aK7uTg
```

**JWE 5개 부분 분석**

**JWE 구조 분해**
```javascript
const jweResponse = "eyJhbGci...YuJKcPwD1BvS5fN8aK7uTg";
const [protected, encryptedKey, iv, ciphertext, tag] = jweResponse.split('.');

console.log("Protected Header:", protected);
console.log("Encrypted Key:", encryptedKey);  
console.log("IV:", iv);
console.log("Ciphertext:", ciphertext);
console.log("Tag:", tag);
```

**1) Protected Header**

**원문 (Base64URL 인코딩)**
```
eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImlUbTZ6Rk9hT0pxSGtYNHo4N0hXaUVkX0hLQnZxNmNWYTlCcUlkVjU1NE0iLCJ5IjoiOXoyX1VDVUN4eXVxVElqQlZoQ3RNUWFnYktOaUF0N2x5a0pBNklPNnc4cyJ9fQ
```

**복호화 후 (JSON)**
```json
{
  "alg": "ECDH-ES",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "iTm6zFOaOJqHkX4z87HWiEd_HKBvq6cVa9BqIdV554M",
    "y": "9z2_UCUCxyuqTIjBVhCtMQagbKNiAt7lykJA6IO6w8s",
    "mb_key": "zDnaekGZTbQBerwcehBSXLqkUBvy6L73p1CJ92BZyK3TF"
  }
}
```

**각 필드 의미**
```javascript
const headerExplained = {
  "alg": "ECDH-ES",           // 키 합의 알고리즘
  "enc": "A256GCM",           // 콘텐츠 암호화 알고리즘
  "epk": {                    // Ephemeral Public Key (발급자 임시 공개키)
    "kty": "EC",              // 키 타입: Elliptic Curve
    "crv": "P-256",           // 곡선: secp256r1
    "x": "iTm6zFOa...",       // 임시 공개키 x 좌표 (32바이트)
    "y": "9z2_UCUCx..."       // 임시 공개키 y 좌표 (32바이트)
    "mb_key": "zDnaekG..."    // 임시 공개키 Multibase 값
  }
};
```

**2) Encrypted Key**

**원문 (빈 문자열)**
```
""
```

**의미**
```javascript
// ECDH-ES에서는 항상 빈 문자열
// 이유: CEK가 ECDH 공유 비밀에서 직접 파생되므로 
//      별도로 암호화된 키가 필요 없음

if (algorithm === "ECDH-ES") {
  encryptedKey = "";  // 항상 빈 값
} else if (algorithm === "ECDH-ES+A256KW") {
  encryptedKey = "wrapped_cek_base64url";  // AES Key Wrap 적용된 CEK
}
```

**3) Initialization Vector (IV)**

**원문 (Base64URL 인코딩)**
```
xVNrS3ZQaXZQYklNTA
```

**복호화 후 (12바이트 바이너리)**
```javascript
const ivBytes = base64urlDecode("xVNrS3ZQaXZQYklNTA");
console.log("IV Length:", ivBytes.length);  // 12 (AES-GCM 표준)
console.log("IV Hex:", bytesToHex(ivBytes)); // c5536b4b7650695062494d4c

// AES-GCM에서 IV는 12바이트(96비트)가 표준
// 랜덤하게 생성되며 각 암호화마다 고유해야 함
```

**IV 특징**
```javascript
const ivCharacteristics = {
  length: 12,                    // AES-GCM 표준 길이
  uniqueness: "매 암호화마다 고유",
  generation: "암호학적 랜덤",
  reuse: "절대 재사용 금지"
};
```

**4) Ciphertext**

**원문 (Base64URL 인코딩, 매우 긴 문자열)**
```
encrypted_credential_data_base64url_encoded_very_long_string_here_representing_the_actual_credential_and_metadata_that_has_been_encrypted_using_aes_gcm_with_the_derived_cek_from_ecdh_key_agreement
```

**복호화 과정**
```javascript
// 1. Base64URL 디코딩
const ciphertextBytes = base64urlDecode(ciphertext);

// 2. CEK 파생 (Wallet에서)
const sharedSecret = ECDH(walletPrivateKey, issuerEphemeralPublicKey);
const cek = ConcatKDF(sharedSecret, 16, "A256GCM");

// 3. AES-GCM 복호화
const decryptedBytes = AES_GCM_Decrypt(ciphertextBytes, cek, iv, tag);

// 4. JSON 파싱
const credentialResponse = JSON.parse(new TextDecoder().decode(decryptedBytes));
```

**복호화 후 내용 (Credential Response JSON)**
```json
{
  "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imlzc3Vlci1rZXktMDAxIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6ImRpZDpleGFtcGxlOjEyMyIsIm5iZiI6MTY0MTIzNDU2NywiZXhwIjoxNjcyNzcwNTY3LCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZToxMjMiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19fQ.signature",
  "c_nonce": "tZignsnFbp",
  "c_nonce_expires_in": 86400,
  "notification_id": "credential_notification_12345"
}
```

**5) Authentication Tag**

**원문 (Base64URL 인코딩)**
```
YuJKcPwD1BvS5fN8aK7uTg
```

**복호화 후 (16바이트 바이너리)**
```javascript
const tagBytes = base64urlDecode("YuJKcPwD1BvS5fN8aK7uTg");
console.log("Tag Length:", tagBytes.length);  // 16 (AES-GCM 표준)
console.log("Tag Hex:", bytesToHex(tagBytes)); // 62e24a70fc03d41bd2e5f37c68aeee4e

// AES-GCM Authentication Tag
// - 암호화된 데이터의 무결성 보장
// - 변조 감지 기능
// - 복호화 시 검증 필수
```

**Tag 검증 과정**
```javascript
async function verifyAndDecrypt(ciphertext, cek, iv, tag) {
  try {
    // AES-GCM은 복호화 시 자동으로 tag 검증
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      cek,
      concat(ciphertext, tag)  // ciphertext + tag 연결
    );
    return decrypted;  // 성공: 무결성 검증 완료
  } catch (error) {
    throw new Error("Tag verification failed - data tampered");
  }
}
```

**완전한 복호화 결과**

**최종 Verifiable Credential (JWT 복호화)**
```javascript
// credential 필드의 JWT를 추가 파싱
const credentialJWT = credentialResponse.credential;
const [header, payload, signature] = credentialJWT.split('.');

// JWT Header
const jwtHeader = JSON.parse(base64urlDecode(header));
console.log("JWT Header:", jwtHeader);

// JWT Payload (실제 Verifiable Credential)
const vcPayload = JSON.parse(base64urlDecode(payload));
console.log("VC Payload:", vcPayload);
```

**JWT Header**
```json
{
  "alg": "ES256",
  "typ": "JWT", 
  "kid": "issuer-key-001"
}
```

**JWT Payload (실제 Verifiable Credential)**
```json
{
  "iss": "https://issuer.example.com",
  "sub": "did:example:123",
  "nbf": 1641234567,
  "exp": 1672770567,
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
      "VerifiableCredential", 
      "UniversityDegreeCredential"
    ],
    "credentialSubject": {
      "id": "did:example:123",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts",
        "university": "Example University",
        "graduationDate": "2024-05-15"
      }
    }
  }
}
```
