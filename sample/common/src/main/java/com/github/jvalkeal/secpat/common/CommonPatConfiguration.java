package com.github.jvalkeal.secpat.common;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.github.jvalkeal.secpat.pat.authorization.InMemoryPatAuthorizationRepository;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorization;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationRepository;
import com.github.jvalkeal.secpat.pat.keygen.OrgTypeChecksumBase62PatGenerationService;
import com.github.jvalkeal.secpat.pat.keygen.PatGenerator;
import com.github.jvalkeal.secpat.pat.keygen.PatMatcher;
import com.github.jvalkeal.secpat.pat.keygen.PatService;
import com.github.jvalkeal.secpat.pat.keygen.UUIDPatService;

@Configuration(proxyBeanMethods = false)
@Profile("patsfromjava")
public class CommonPatConfiguration {

	private final static Logger log = LoggerFactory.getLogger(CommonPatConfiguration.class);

	@Bean
	public PatAuthorizationRepository patAuthorizationService() {
		PatService fakeUserPatService = new FakeUserPatService();
		PatService uuidPatService = new UUIDPatService();
		PatService checksumPatService = new OrgTypeChecksumBase62PatGenerationService("myorg", "pat", 51);
		PatGenerator generator = fakeUserPatService.generator();
		InMemoryPatAuthorizationRepository repository = new InMemoryPatAuthorizationRepository();
		Instant now = Instant.now();
		Instant month = now.plus(30, ChronoUnit.DAYS);
		Instant sec = now.plus(1, ChronoUnit.SECONDS);
		Instant monthMinusDay = month.minus(1, ChronoUnit.DAYS);
		Instant nowMinus1Day = now.minus(1, ChronoUnit.DAYS);
		Instant nowMinus2Days = now.minus(1, ChronoUnit.DAYS);
		repository.save(PatAuthorization.builder().principal("user1").scopes(new HashSet<>(Arrays.asList("read"))).token(generator.apply("user1")).issuedAt(now).expiresAt(month).notBefore(now).build());
		repository.save(PatAuthorization.builder().principal("user2").scopes(new HashSet<>(Arrays.asList("write"))).token(generator.apply("user2")).issuedAt(now).expiresAt(month).notBefore(now).build());
		repository.save(PatAuthorization.builder().principal("user3").scopes(new HashSet<>(Arrays.asList("write"))).token(generator.apply("user3")).issuedAt(now).expiresAt(sec).notBefore(now).build());
		repository.save(PatAuthorization.builder().principal("user4").scopes(new HashSet<>(Arrays.asList("write"))).token(generator.apply("user4")).issuedAt(now).expiresAt(month).notBefore(monthMinusDay).build());
		repository.save(PatAuthorization.builder().principal("user5").scopes(new HashSet<>(Arrays.asList("read"))).token(generator.apply("user5")).issuedAt(nowMinus2Days).expiresAt(nowMinus1Day).notBefore(nowMinus2Days).build());
		String token6 = uuidPatService.generator().apply(null);
		repository.save(PatAuthorization.builder().principal("user6").scopes(new HashSet<>(Arrays.asList("read"))).token(token6).issuedAt(now).expiresAt(month).notBefore(now).build());
		String token7 = checksumPatService.generator().apply(null);
		repository.save(PatAuthorization.builder().principal("user7").scopes(new HashSet<>(Arrays.asList("read"))).token(token7).issuedAt(now).expiresAt(month).notBefore(now).build());
		log.info("Generated token {} {}", "user6", token6);
		log.info("Generated token {} {}", "user7", token7);
		return repository;
	}

	/**
	 * Needed to fake that we've randomly generated these tokens.
	 */
	static class FakeUserPatService implements PatService {

		@Override
		public PatGenerator generator() {
			return source -> {
				if (source instanceof String user) {
					String token = switch (user) {
						case "user1" -> "pat1111";
						case "user2" -> "pat2222";
						case "user3" -> "pat3333";
						case "user4" -> "pat4444";
						case "user5" -> "pat5555";
						default -> null;
					};
					if (token != null) {
						return token;
					}
				}
				return null;
			};
		}

		@Override
		public PatMatcher matcher() {
			return token -> {
				return token != null && token.startsWith("pat");
			};
		}

	}

}
