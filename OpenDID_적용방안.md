# OID4VC 적용 방안 분석 보고서

## 1. 개요

본 문서는 `oid4vc_analysis.md` 분석 결과를 바탕으로, 기존 DID VC 시스템(`did-issuer-server`, `did-verifier-server`, `did-client-sdk-aos` 등)에 OID4VC 표준(OID4VCI, OID4VP, SIOPv2)을 적용하기 위한 구체적인 실행 방안을 기술한다. 목표는 EUDIW 등 글로벌 디지털 지갑과의 상호운용성을 확보하고, 개방형 표준을 준수하여 시스템을 고도화하는 것이다.

## 2. 목표 시스템 아키텍처

OID4VC 표준을 적용하기 위해 기존 시스템 구성에 **Authorization Server (AS)** 를 추가하고, 각 컴포넌트의 역할을 재정의해야 한다.

- **Authorization Server (신규 개발)**: OAuth 2.0 기반의 인가/인증을 전담하는 서버. VC 발급 시 사용자의 동의를 얻고 Access Token을 발급하는 핵심 역할을 수행한다.
- **did-issuer-server (기능 변경)**: OID4VCI 표준에 따라 VC를 발급하는 **Resource Server** 역할을 수행한다. AS가 발급한 Access Token을 검증하여 VC를 발급한다.
- **did-verifier-server (기능 변경)**: OID4VP 표준에 따라 VP를 요청하고 검증하는 **Verifier** 역할을 수행한다.
- **did-client-sdk-aos (기능 변경)**: 사용자의 Wallet으로서 OID4VCI의 **Client**, OID4VP의 **Prover**, SIOPv2의 **Self-Issued OpenID Provider** 역할을 모두 수행한다.
- **did-ca-aos / did-ta-server (역할 유지)**: DID 발급 및 신뢰 검증을 위한 인프라로서, DID Resolution 과정에서 기존 역할을 그대로 유지한다.

## 3. 신규 개발 요구사항

### 3.1. Authorization Server (AS) 구현

기존 시스템에는 OAuth 2.0 표준을 지원하는 독립적인 Authorization Server가 부재하므로 신규 개발이 필수적이다.

- **주요 기능:**
    - **OAuth 2.0 표준 엔드포인트 구현:**
        - `/authorize`: 사용자의 인증 및 동의를 처리하고 Authorization Code를 발급한다.
        - `/token`: Authorization Code 또는 Pre-authorized Code를 Access Token, Refresh Token으로 교환한다.
    - **클라이언트 관리:** Wallet 등 OAuth 2.0 클라이언트의 등록 및 관리 기능.
    - **사용자 인증:** VC 발급을 요청하는 사용자를 인증하는 기능 (ID/PW, 생체인증 등).
    - **토큰 관리:** Access Token 및 Refresh Token의 발급, 검증, 만료 정책 관리.
    - **PKCE 지원:** Authorization Code 탈취 공격을 방지하기 위한 PKCE(Proof Key for Code Exchange) 지원.

## 4. 기존 오픈소스 변경 요구사항

### 4.1. `did-issuer-server` → OID4VCI Issuer 역할로 변경

- **엔드포인트 구현:** OID4VCI 표준에 따라 다음 엔드포인트를 구현해야 한다.
    - `/.well-known/openid-credential-issuer` (GET): Issuer의 정책과 기술 사양(지원하는 VC 종류, 엔드포인트 주소, 암호화 방식 등)을 담은 **Issuer Metadata**를 제공한다.
    - `/credential_offer` (GET/POST): Wallet에 VC 발급 제안(Credential Offer)을 전달한다.
    - `/credential` (POST): Wallet으로부터 Access Token과 `proof`가 포함된 VC 발급 요청을 받아 처리한다.
    - (선택) `/nonce`, `/deferred_credential`, `/notification` 등 부가 엔드포인트 구현.
- **프로토콜 변경:**
    - **Access Token 검증:** VC 발급 요청 시 `Authorization` 헤더에 포함된 Access Token을 AS에 검증 요청하는 로직을 추가해야 한다.
    - **VC 발급 흐름 지원:**
        - **Authorization Code Flow:** AS를 통한 사용자 인증/동의 후 발급하는 흐름을 지원한다.
        - **Pre-authorized Code Flow:** 외부 채널을 통해 사전 인증된 `pre-authorized_code`를 이용해 즉시 토큰을 교환하고 VC를 발급하는 흐름을 지원한다.
    - **Holder Binding:** VC 발급 요청의 `proof` 파라미터(JWT 형식)를 검증하여, VC가 정당한 소유자(Holder)에게 발급되는지 확인하는 로직을 구현해야 한다.

### 4.2. `did-verifier-server` → OID4VP Verifier 역할로 변경

- **프로토콜 변경:** 기존의 독자적인 VP 제출 프로토콜을 OID4VP 표준으로 대체한다.
    - **Presentation Request 생성:**
        - `request_uri`를 동적으로 생성하여 Wallet에 전달하는 기능을 구현한다. 이 `request_uri`는 JWT 형식의 요청 객체를 가리키며, 내부에 `presentation_definition`을 포함한다.
        - **Presentation Definition** 또는 **DCQL**을 사용하여 요청할 VC의 조건(종류, 클레임, 발급자 등)을 명세하는 기능을 구현한다.
    - **VP Token 수신 및 검증:**
        - Wallet이 제출한 `vp_token`(JWT 형식) 또는 ID Token에 포함된 VP를 수신하는 엔드포인트(`response_uri` 또는 `client_id`로 지정된 경로)를 구현한다.
        - 수신된 VP Token의 서명, `nonce`, `aud` 등을 검증하고, 내부에 포함된 VP와 VC의 유효성을 검증하는 로직을 구현한다.
    - **Cross/Same Device Flow 지원:** QR 코드 생성, Custom App Scheme을 통한 딥링킹 등 다양한 사용자 환경을 지원하기 위한 로직이 필요하다.

### 4.3. `did-client-sdk-aos` (Wallet) → OID4VC/SIOPv2 Client 역할로 변경

- **OID4VCI 클라이언트 기능:**
    - Credential Offer(`credential_offer` 또는 `credential_offer_uri`)를 해석하고, Issuer Metadata를 조회하여 발급 절차를 시작하는 기능을 구현한다.
    - `authorization_details` 또는 `scope`를 사용하여 AS에 인가 요청을 보내고, `redirect_uri`를 통해 Authorization Code를 수신한다.
    - 획득한 Code를 AS의 Token Endpoint로 보내 Access Token을 발급받는다.
    - VC에 Holder의 DID를 바인딩하기 위해 개인키로 서명한 `proof`(JWT 형식)를 생성하고, Access Token과 함께 Issuer의 Credential Endpoint로 전송하여 VC를 발급받는다.
- **OID4VP 클라이언트 (Prover) 기능:**
    - Verifier가 제시한 `request_uri`를 해석하여 `presentation_definition`을 파악한다.
    - `presentation_definition`의 요구사항과 일치하는 VC를 로컬 저장소에서 검색한다.
    - 사용자의 동의를 얻어 VP를 생성하고, 이를 `vp_token`(JWT)으로 패키징한다. 이때 Verifier가 요청한 `nonce`를 포함하여 서명한다.
    - 생성된 `vp_token`을 Verifier가 지정한 `response_uri`로 전송한다.
- **SIOPv2 Provider 기능:**
    - OID4VCI/OID4VP 과정에서 신원 인증이 필요할 때, 자신의 DID를 `iss`와 `sub`으로 하는 **ID Token**을 생성하고 개인키로 서명하는 기능을 구현한다.
    - 이 ID Token은 Client Authentication 또는 Subject 인증 용도로 사용된다.

## 5. 데이터 모델 및 프로토콜 표준화

- **JWT 전환:** 시스템 내에서 교환되는 모든 핵심 데이터(VC, VP, ID Token, `proof` 등)는 **JWT 형식**으로 통일한다.
- **보안 표준 적용:** 데이터 보호를 위해 필요에 따라 **JWS(서명)**, **JWE(암호화)**, **JWK(키 표현)** 표준을 적용한다.
- **기존 프로토콜 폐기:** OID4VC 표준 도입에 따라, 기존의 독자적인 VC/VP 교환 프로토콜은 점진적으로 폐기하고 OID4VCI/OID4VP로 완전히 대체한다.

## 6. 단계별 적용 로드맵 (제안)

1.  **1단계: 기반 구축 (Authorization Server & SIOPv2)**
    - 독립적인 Authorization Server를 신규 개발하고 OAuth 2.0 핵심 기능을 구현한다.
    - `did-client-sdk-aos`에 SIOPv2 기반의 ID Token 생성 및 서명 기능을 구현하여 기본 인증 체계를 마련한다.

2.  **2단계: VC 발급 표준화 (OID4VCI)**
    - `did-issuer-server`에 OID4VCI Issuer 엔드포인트 및 로직을 구현한다.
    - `did-client-sdk-aos`에 OID4VCI Client 로직을 구현하여 AS 및 Issuer와 연동 테스트를 진행한다.

3.  **3단계: VP 제출 표준화 (OID4VP)**
    - `did-verifier-server`에 OID4VP Verifier 로직(요청 생성, VP 검증)을 구현한다.
    - `did-client-sdk-aos`에 OID4VP Prover 로직(요청 해석, VP 생성/제출)을 구현한다.

## 7. 결론

OID4VC 표준 적용은 단순한 프로토콜 변경을 넘어, 시스템 아키텍처 전반의 재설계가 필요한 중요한 과제이다. 제안된 방안에 따라 신규 Authorization Server를 개발하고 기존 오픈소스들을 OID4VC 역할에 맞게 변경함으로써, 글로벌 표준을 준수하고 상호운용성을 갖춘 신뢰할 수 있는 DID 시스템으로 발전할 수 있을 것이다.
