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

### 4.4 SIOPv2 // 아래 세부 목차는 자유롭게 바꾸셔도 됩니다.
#### 4.4.1 개요 및 역할
#### 4.4.2 OID4VCI에서의 Client Authentication 방식으로 사용
#### 4.4.3 OID4VP에서의 Subject 인증 방식으로 사용
#### 4.4.4 ID Token 발급 구조 (JWT + DID)
#### 4.4.5 SIOP 기반 Wallet의 검증 흐름


## 5. OID4VC 적용 전략


## 6. 부록
