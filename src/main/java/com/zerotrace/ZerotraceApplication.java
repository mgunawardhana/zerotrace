package com.zerotrace;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import java.security.Security;

@SpringBootApplication
@EnableWebSecurity
@EnableJpaAuditing
@EnableTransactionManagement
@EnableAsync
public class ZerotraceApplication {

	@PostConstruct
	public void init() {
		/* Add BouncyCastle as security provider for advanced cryptographic operations */
		Security.addProvider(new BouncyCastleProvider());

		/* Set system properties for enhanced security */
		System.setProperty("java.security.egd", "file:/dev/./urandom");
		System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
		System.setProperty("jdk.tls.ephemeralDHKeySize", "2048");

		/* Disable unnecessary features for security */
		System.setProperty("spring.devtools.restart.enabled", "false");
		System.setProperty("spring.devtools.livereload.enabled", "false");
	}

	public static void main(String[] args) {
		/* Additional security system properties */
		System.setProperty("file.encoding", "UTF-8");
		System.setProperty("user.timezone", "UTC");

		SpringApplication app = new SpringApplication(ZerotraceApplication.class);
		app.setAdditionalProfiles("secure");
		app.run(args);
	}

}
