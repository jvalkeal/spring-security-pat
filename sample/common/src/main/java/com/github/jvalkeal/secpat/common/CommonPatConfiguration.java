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

import com.github.jvalkeal.secpat.pat.authorization.InMemoryPatAuthorizationService;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorization;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationService;
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
	public PatAuthorizationService patAuthorizationService() {
		PatService fakeUserPatService = new FakeUserPatService();
		PatService uuidPatService = new UUIDPatService();
		PatService checksumPatService = new OrgTypeChecksumBase62PatGenerationService("myorg", "pat", 51);
		PatGenerator generator = fakeUserPatService.generator();
		InMemoryPatAuthorizationService service = new InMemoryPatAuthorizationService();
		Instant now = Instant.now();
		Instant month = now.plus(30, ChronoUnit.DAYS);
		Instant sec = now.plus(1, ChronoUnit.SECONDS);
		Instant monthMinusDay = month.minus(1, ChronoUnit.DAYS);
		Instant nowMinus1Day = now.minus(1, ChronoUnit.DAYS);
		Instant nowMinus2Days = now.minus(1, ChronoUnit.DAYS);
		service.save(new PatAuthorization("user1", new HashSet<>(Arrays.asList("read")), generator.apply("user1"), now, month, now));
		service.save(new PatAuthorization("user2", new HashSet<>(Arrays.asList("write")), generator.apply("user2"), now, month, now));
		service.save(new PatAuthorization("user3", new HashSet<>(Arrays.asList("write")), generator.apply("user3"), now, sec, now));
		service.save(new PatAuthorization("user4", new HashSet<>(Arrays.asList("write")), generator.apply("user4"), now, month, monthMinusDay));
		service.save(new PatAuthorization("user5", new HashSet<>(Arrays.asList("read")), generator.apply("user5"), nowMinus2Days, nowMinus1Day, nowMinus2Days));
		String token6 = uuidPatService.generator().apply(null);
		service.save(new PatAuthorization("user6", new HashSet<>(Arrays.asList("read")), token6, now, month, now));
		String token7 = checksumPatService.generator().apply(null);
		service.save(new PatAuthorization("user7", new HashSet<>(Arrays.asList("read")), token7, now, month, now));
		log.info("Generated token {} {}", "user6", token6);
		log.info("Generated token {} {}", "user7", token7);
		return service;
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
