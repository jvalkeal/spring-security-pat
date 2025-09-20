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

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

class JdbcPatAuthorizationServiceTests {

	private static final String PAT_AUTHORIZATIONS_SCHEMA_SQL_RESOURCE = "/com/github/jvalkeal/secpat/pat/authorization/pat-authorization-service-schema.sql";

	private EmbeddedDatabase db;

	private JdbcOperations jdbcOperations;

	private JdbcPatAuthorizationService patAuthorizationService;

	@BeforeEach
	public void setUp() {
		this.db = createDb(PAT_AUTHORIZATIONS_SCHEMA_SQL_RESOURCE);
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.patAuthorizationService = new JdbcPatAuthorizationService(this.jdbcOperations);
	}

	@AfterEach
	public void tearDown() {
		if (this.db != null) {
			this.db.shutdown();
		}
	}

	@Test
	void test() {
		Instant now = Instant.now();
		PatAuthorization in = PatAuthorization.builder().name("name1").principal("user1").scopes(new HashSet<>(Arrays.asList("read")))
				.token("pat1234").issuedAt(now).expiresAt(now).notBefore(now).build();
		this.patAuthorizationService.save(in);
		PatAuthorization out = this.patAuthorizationService.find("pat1234");
		assertThat(out).isNotNull();
		assertThat(out.getToken()).isEqualTo(in.getToken());

		this.patAuthorizationService.remove(out);
		out = this.patAuthorizationService.find("pat1234");
		assertThat(out).isNull();
	}

	private static EmbeddedDatabase createDb(String schema) {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript(schema)
				.build();
		// @formatter:on
	}

}
