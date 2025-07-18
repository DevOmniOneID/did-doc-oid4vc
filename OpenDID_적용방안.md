# OID4VC 적용 방안 및 전략

## 1. 개요

본 문서는 OID4VC 분석 결과를 바탕으로, 기존 DID VC 시스템에 OID4VC 표준(OID4VCI, OID4VP, SIOPv2)을 적용하기 위한 구체적인 실행 방안과 전략을 기술함. 목표는 EUDI Wallet 등 글로벌 디지털 지갑과의 상호운용성을 확보하고, 개방형 표준을 준수하여 시스템을 고도화하는 것임.

## 2. 목표 시스템 아키텍처

OID4VC 표준을 적용하기 위해 기존 시스템 구성에 **Authorization Server (AS)** 를 추가하고, 각 컴포넌트의 역할을 재정의해야 함.

- **Authorization Server (신규 개발)**: OAuth 2.0 기반의 인가/인증을 전담하는 서버. VC 발급 시 사용자의 동의를 얻고 Access Token을 발급하는 핵심 역할을 수행함.
- **did-issuer-server (기능 변경)**: OID4VCI 표준에 따라 VC를 발급하는 **Resource Server** 역할을 수행함. AS가 발급한 Access Token을 검증하여 VC를 발급함.
- **did-verifier-server (기능 변경)**: OID4VP 표준에 따라 VP를 요청하고 검증하는 **Verifier** 역할을 수행함.
- **did-ca-aos / did-client-sdk-aos (기능 변경)**: 사용자의 Wallet으로서 OID4VCI의 **Client**, OID4VP의 **Prover**, SIOPv2의 **Self-Issued OpenID Provider** 역할을 모두 수행함.
- **did-ta-server (역할 유지)**: DID 발급 및 신뢰 검증을 위한 인프라로서, DID Resolution 과정에서 기존 역할을 그대로 유지함.

## 3. 신규 개발 요구사항

### 3.1. Authorization Server (AS) 구현

기존 시스템에는 OAuth 2.0 표준을 지원하는 독립적인 Authorization Server가 부재하므로 신규 개발이 필수적임.

- **주요 기능:**
    - **OAuth 2.0 표준 엔드포인트 구현:**
        - `/authorize`: 사용자의 인증 및 동의를 처리하고 Authorization Code를 발급함.
        - `/token`: Authorization Code 또는 Pre-authorized Code를 Access Token, Refresh Token으로 교환함.
    - **클라이언트 관리:** Wallet 등 OAuth 2.0 클라이언트의 등록 및 관리 기능.
    - **사용자 인증:** VC 발급을 요청하는 사용자를 인증하는 기능 (ID/PW, 생체인증 등).
    - **토큰 관리:** Access Token 및 Refresh Token의 발급, 검증, 만료 정책 관리.
    - **PKCE 지원:** Authorization Code 탈취 공격을 방지하기 위한 PKCE(Proof Key for Code Exchange) 지원.

## 4. 기존 오픈소스 변경 요구사항

### 4.1. `VC 발급 프로토콜에서` `TAS` 경유 → `Issuer 직접 접근` 혹은 `Proxy 서버 경유`로 분리
- **Issuer 직접 접근:** OID4VCI Issuer 엔드포인트 구현 주체가 TAS가 될 수 없으므로, Issuer 직접 접근으로 구조 변경 필수.
- **Proxy 서버 경유:** Issuer 직접 접근이 구조적으로 어려운 경우, Reverse Proxy 서버 등을 통한 Issuer 중개 가능.

### 4.2. `did-issuer-server` → OID4VCI Issuer 역할로 변경

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

### 4.3. `did-verifier-server` → OID4VP Verifier 역할로 변경

- **프로토콜 변경:** 기존의 독자적인 VP 제출 프로토콜을 OID4VP 표준으로 대체함.
    - **Presentation Request 생성:**
        - `request_uri`를 동적으로 생성하여 Wallet에 전달하는 기능을 구현함. 이 `request_uri`는 JWT 형식의 요청 객체를 가리키며, 내부에 `presentation_definition`을 포함함.
        - **Presentation Definition** 또는 **DCQL**을 사용하여 요청할 VC의 조건(종류, 클레임, 발급자 등)을 명세하는 기능을 구현함.
    - **VP Token 수신 및 검증:**
        - Wallet이 제출한 `vp_token`(JWT 형식) 또는 ID Token에 포함된 VP를 수신하는 엔드포인트(`response_uri` 또는 `client_id`로 지정된 경로)를 구현함.
        - 수신된 VP Token의 서명, `nonce`, `aud` 등을 검증하고, 내부에 포함된 VP와 VC의 유효성을 검증하는 로직을 구현함.
    - **Cross/Same Device Flow 지원:** QR 코드 생성, Custom App Scheme을 통한 딥링킹 등 다양한 사용자 환경을 지원하기 위한 로직이 필요함.

### 4.4. `did-ca-aos` (CA) + `did-client-sdk-aos` (Wallet) → OID4VC/SIOPv2 Client 역할로 변경

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

## 5. 데이터 모델 및 프로토콜 표준화

- **JWT 전환:** 시스템 내에서 교환되는 모든 핵심 데이터(VC, VP, ID Token, `proof` 등)는 **JWT 형식**으로 통일함.
- **보안 표준 적용:** 데이터 보호를 위해 필요에 따라 **JWS(서명)**, **JWE(암호화)**, **JWK(키 표현)** 표준을 적용함.
- **기존 프로토콜 폐기:** OID4VC 표준 도입에 따라, 기존의 독자적인 VC/VP 교환 프로토콜은 점진적으로 폐기하고 OID4VCI/OID4VP로 완전히 대체함.

## 6. OID4VC 적용 전략

### 6.1. 점진적 적용 전략 (Phased Approach)

OID4VC 표준이 아직 `draft` 상태인 점을 고려하여, 안정성과 유연성을 모두 확보할 수 있는 점진적 적용 전략을 채택함.

- **1단계: 핵심 기반 구축 (MVP)**
    - **목표:** 가장 안정적이고 핵심적인 기능 우선 구현.
    - **내용:**
        1.  **Authorization Server 신규 개발:** OAuth 2.0의 핵심 기능(`authorization_code` grant type, token 발급)을 우선 구현함.
        2.  **SIOPv2 구현:** `did-client-sdk-aos`에 DID 기반의 ID Token 생성 및 서명 기능을 구현하여, 기본적인 Self-Sovereign 인증 체계를 마련함.
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

### 6.2. 상호운용성 확보 전략

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
    
## 7. 결론

OID4VC 표준 적용은 단순한 프로토콜 변경을 넘어, 시스템 아키텍처 전반의 재설계가 필요한 중요한 과제임. 제안된 방안에 따라 신규 Authorization Server를 개발하고 기존 오픈소스들을 OID4VC 역할에 맞게 변경하여야 함.

또한 OID4VC 표준의 `draft` 상태와 글로벌 상호운용성의 중요성을 고려할 때, **점진적이고 유연한 적용 전략**이 필수적임. 제안된 단계별 로드맵과 상호운용성 확보 전략에 따라 시스템을 개발하고 발전시켜 나간다면, 변화하는 표준 환경에 성공적으로 적응하고 글로벌 경쟁력을 갖춘 DID 시스템을 구축할 수 있을 것임.
