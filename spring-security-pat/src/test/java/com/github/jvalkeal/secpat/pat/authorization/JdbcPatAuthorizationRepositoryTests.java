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

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

class JdbcPatAuthorizationRepositoryTests extends BasePatAuthorizationRepositoryTests {

	private static final String PAT_AUTHORIZATIONS_SCHEMA_SQL_RESOURCE = "/com/github/jvalkeal/secpat/pat/authorization/pat-authorization-service-schema.sql";

	private EmbeddedDatabase db;

	private JdbcOperations jdbcOperations;

	@Override
	PatAuthorizationRepository createRepository() {
		return new JdbcPatAuthorizationRepository(this.jdbcOperations);
	}


	@Override
	void doSetup() {
		this.db = createDb(PAT_AUTHORIZATIONS_SCHEMA_SQL_RESOURCE);
		this.jdbcOperations = new JdbcTemplate(this.db);
	}

	@Override
	void doTearDown() {
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
