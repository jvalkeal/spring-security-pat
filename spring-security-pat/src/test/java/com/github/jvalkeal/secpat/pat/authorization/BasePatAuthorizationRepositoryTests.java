/*
 * Copyright 2025-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.jvalkeal.secpat.pat.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

abstract class BasePatAuthorizationRepositoryTests {

	PatAuthorizationRepository repository;

	@BeforeEach
	void setup() {
		doSetup();
		this.repository = createRepository();
	}

	@AfterEach
	public void tearDown() {
		doTearDown();
	}

	abstract void doSetup();

	abstract void doTearDown();

	abstract PatAuthorizationRepository createRepository();

	@Test
	void saveAndFindById() {
		repository.save(ofId("id1"));
		PatAuthorization pa = repository.findById("id1");
		assertThat(pa).isNotNull();
	}

	@Test
	void saveAndFindByToken() {
		repository.save(ofToken("pat1234"));
		PatAuthorization pa = repository.findByToken("pat1234");
		assertThat(pa).isNotNull();
	}

	@Test
	void saveAndRemove() {
		PatAuthorization pa = ofId("id");
		repository.save(pa);
		repository.remove(pa);
		assertThat(repository.findById("id")).isNull();
	}

	@Test
	void cantSaveWithSameToken() {
		repository.save(ofId("id"));
		assertThatThrownBy(() -> {
			repository.save(ofId("id"));
		}).isInstanceOf(RuntimeException.class);
	}

	@Test
	void findOnlyUserWithUserPrincipal() {
		repository.save(ofPrincipal("user1"));
		repository.save(ofPrincipal("user1"));
		repository.save(ofPrincipal("user2"));
		assertThat(repository.findByPrincipal("user1")).hasSize(2);
		assertThat(repository.findByPrincipal("user2")).hasSize(1);
		assertThat(repository.findByPrincipal("user3")).hasSize(0);
	}

	private static PatAuthorization ofId(String id) {
		Instant now = Instant.now();
		return PatAuthorization.builder()
			.id(id)
			.name("name")
			.principal("user1")
			.scope("test")
			.token("pat1234")
			.issuedAt(now)
			.expiresAt(now)
			.notBefore(now)
			.build();
	}

	private static PatAuthorization ofToken(String token) {
		Instant now = Instant.now();
		return PatAuthorization.builder()
			.id("id")
			.name("name")
			.principal("user1")
			.scope("test")
			.token(token)
			.issuedAt(now)
			.expiresAt(now)
			.notBefore(now)
			.build();
	}

	private static PatAuthorization ofPrincipal(String principal) {
		Instant now = Instant.now();
		return PatAuthorization.builder()
			.id(UUID.randomUUID().toString())
			.name("name")
			.principal(principal)
			.scope("test")
			.token(UUID.randomUUID().toString())
			.issuedAt(now)
			.expiresAt(now)
			.notBefore(now)
			.build();
	}

}
