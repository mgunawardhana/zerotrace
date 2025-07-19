<div align="center">

  <h1 align="center">ZeroTrace Crypto Wallet</h1>
  <img src="https://github.com/user-attachments/assets/6070fd43-2638-446a-9bff-5b6b8f29e2e7">
  <p align="center">
    A secure, reliable, and developer-friendly backend service for a modern digital wallet.
  </p>
</div>

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java Version](https://img.shields.io/badge/Java-17-blue.svg)](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Maven](https://img.shields.io/badge/Maven-3.8-red.svg)](https://maven.apache.org/)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://www.docker.com/)

</div>

---

## 📖 Table of Contents

* [Welcome](#welcome-crypto-enthusiasts-and-developers-)
* [Introduction](#-introduction)
* [Features](#-features)
* [Technology Stack](#-technology-stack)
* [Project Structure](#-project-structure)
* [Getting Started](#-getting-started)
* [API Endpoints](#-api-endpoints)
* [Security Overview](#-security-overview)
* [Contributing](#-contributing)
* [License](#-license)

---

## Welcome Crypto Enthusiasts and Developers! 👋

We are thrilled to welcome you to the **ZeroTrace Crypto Wallet** project. Whether you're a seasoned blockchain developer, a backend engineer, or a crypto enthusiast with a passion for secure systems, we invite you to explore, contribute, and help us build the future of decentralized finance. Your expertise and passion are warmly welcomed here.

---

## 📜 Introduction

ZeroTrace Crypto Wallet is a secure and reliable backend service for a modern digital wallet. This project is built with **Spring Boot** and leverages a suite of powerful technologies to provide a robust platform for managing digital assets. Our primary goal is to create a secure, scalable, and user-friendly wallet that developers can build upon and users can trust.

---

## ✨ Features

* **Secure User Authentication:** Stateless authentication using JSON Web Tokens (JWT).
* **End-to-End Encryption:** Robust cryptographic services for data protection.
* **Wallet Management:** Create, retrieve, and manage digital wallets securely.
* **Transaction Handling:** A secure system for processing and recording transactions.
* **Comprehensive Auditing:** Detailed logging of all significant actions for security and traceability.
* **Database Migration:** Managed database schema evolution using Flyway.
* **Containerization:** Full Docker support for easy deployment, scaling, and environment consistency.

---

## 💻 Technology Stack

| Category          | Technology                                                                                             |
| ----------------- | ------------------------------------------------------------------------------------------------------ |
| **Backend** | [Spring Boot 3.x](https://spring.io/projects/spring-boot)                                              |
| **Language** | [Java 17](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)                |
| **Database** | [PostgreSQL](https://www.postgresql.org/)                                                              |
| **DB Migration** | [Flyway](https://flywaydb.org/)                                                                        |
| **Authentication**| [Spring Security](https://spring.io/projects/spring-security), [JSON Web Tokens (JWT)](https://jwt.io/)|
| **Cryptography** | [Bouncy Castle](https://www.bouncycastle.org/)                                                         |
| **Build Tool** | [Maven](https://maven.apache.org/)                                                                     |
| **Containerization**| [Docker](https://www.docker.com/), [Docker Compose](https://docs.docker.com/compose/)                 |

---

## 📂 Project Structure

Here is the detailed structure of the project, designed for clarity and separation of concerns.

```
crypto-wallet-backend/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── cryptowallet/
│   │   │           ├── CryptoWalletApplication.java
│   │   │           ├── config/
│   │   │           │   ├── SecurityConfig.java
│   │   │           │   ├── DatabaseConfig.java
│   │   │           │   ├── EncryptionConfig.java
│   │   │           │   └── AuditConfig.java
│   │   │           ├── controller/
│   │   │           │   ├── AuthController.java
│   │   │           │   ├── WalletController.java
│   │   │           │   └── TransactionController.java
│   │   │           ├── service/
│   │   │           │   ├── AuthService.java
│   │   │           │   ├── WalletService.java
│   │   │           │   ├── TransactionService.java
│   │   │           │   ├── EncryptionService.java
│   │   │           │   ├── KeyManagementService.java
│   │   │           │   └── AuditService.java
│   │   │           ├── repository/
│   │   │           │   ├── UserRepository.java
│   │   │           │   ├── WalletRepository.java
│   │   │           │   ├── TransactionRepository.java
│   │   │           │   └── AuditLogRepository.java
│   │   │           ├── entity/
│   │   │           │   ├── User.java
│   │   │           │   ├── Wallet.java
│   │   │           │   ├── Transaction.java
│   │   │           │   └── AuditLog.java
│   │   │           ├── dto/
│   │   │           │   ├── request/
│   │   │           │   │   ├── LoginRequest.java
│   │   │           │   │   ├── CreateWalletRequest.java
│   │   │           │   │   └── TransactionRequest.java
│   │   │           │   └── response/
│   │   │           │       ├── AuthResponse.java
│   │   │           │       ├── WalletResponse.java
│   │   │           │       └── TransactionResponse.java
│   │   │           ├── security/
│   │   │           │   ├── JwtTokenProvider.java
│   │   │           │   ├── JwtAuthenticationFilter.java
│   │   │           │   ├── CustomUserDetailsService.java
│   │   │           │   ├── RSAKeyGenerator.java
│   │   │           │   └── SecureRandomGenerator.java
│   │   │           ├── crypto/
│   │   │           │   ├── AESEncryption.java
│   │   │           │   ├── RSAEncryption.java
│   │   │           │   ├── HashUtils.java
│   │   │           │   └── KeyDerivation.java
│   │   │           ├── exception/
│   │   │           │   ├── GlobalExceptionHandler.java
│   │   │           │   ├── CryptoException.java
│   │   │           │   └── SecurityException.java
│   │   │           └── util/
│   │   │               ├── ValidationUtils.java
│   │   │               └── Constants.java
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── application-prod.yml
│   │       └── db/
│   │           └── migration/
│   │               ├── V1__create_users_table.sql
│   │               ├── V2__create_wallets_table.sql
│   │               ├── V3__create_transactions_table.sql
│   │               └── V4__create_audit_logs_table.sql
│   └── test/
│       └── java/
│           └── com/
│               └── cryptowallet/
│                   ├── service/
│                   ├── security/
│                   └── crypto/
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── pom.xml
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

* [Java Development Kit (JDK) 17](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)
* [Apache Maven](https://maven.apache.org/download.cgi)
* [Docker](https://www.docker.com/products/docker-desktop/) and [Docker Compose](https://docs.docker.com/compose/install/)

### Installation & Setup

1.  **Clone the Repository**
    ```sh
    git clone [https://github.com/mgunawardhana/crypto-wallet-backend.git](https://github.com/mgunawardhana/crypto-wallet-backend.git)
    cd crypto-wallet-backend
    ```

2.  **Configure Environment**
    Copy the `application.yml` file to `application-dev.yml` for local development settings. Update the database connection details, JWT secret, and other sensitive properties.
    ```sh
    cp src/main/resources/application.yml src/main/resources/application-dev.yml
    ```

3.  **Build the Application**
    Use the Maven wrapper to compile the source code and download dependencies.
    ```sh
    ./mvnw clean install
    ```

4.  **Run the Application**
    * **Directly with Maven:**
        ```sh
        # This will use the 'dev' profile by default
        ./mvnw spring-boot:run
        ```
    * **Using Docker (Recommended):**
        This command will build the Docker image and start the application and its database dependency.
        ```sh
        docker-compose up --build
        ```

---

## 📡 API Endpoints

The API is secured and requires a valid JWT in the `Authorization` header for most endpoints.

| Method | Endpoint                  | Description                                |
| ------ | ------------------------- | ------------------------------------------ |
| `POST` | `/api/auth/register`      | Register a new user.                       |
| `POST` | `/api/auth/login`         | Authenticate and receive a JWT.            |
| `POST` | `/api/wallets`            | Create a new wallet for the authenticated user. |
| `GET`  | `/api/wallets`            | Get all wallets for the authenticated user.|
| `GET`  | `/api/wallets/{walletId}` | Get details for a specific wallet.         |
| `POST` | `/api/transactions`       | Create a new transaction from a wallet.    |
| `GET`  | `/api/transactions/{walletId}` | Get all transactions for a specific wallet.|

---

## 🔒 Security Overview

Security is a core principle of this project.

* **Password Hashing:** User passwords are not stored in plaintext. We use `BCryptPasswordEncoder` to hash and salt passwords before storing them.
* **JWT Authentication:** Secure, stateless authentication is handled using JSON Web Tokens with a strong secret key and appropriate expiration times.
* **Data Encryption:** Sensitive data within the database is encrypted using robust cryptographic algorithms.
* **Input Validation:** All incoming DTOs are validated to prevent common vulnerabilities like Cross-Site Scripting (XSS) and injection attacks.
* **Exception Handling:** A global exception handler prevents stack traces and sensitive information from being exposed in API responses.

---

## 🤝 Contributing

Contributions are what make the open-source community an amazing place to learn, create, and inspire. Any contributions you make are **greatly appreciated**. Please read our contributing guidelines before you start.

1.  Fork the Project.
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the Branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

---

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for more information.
