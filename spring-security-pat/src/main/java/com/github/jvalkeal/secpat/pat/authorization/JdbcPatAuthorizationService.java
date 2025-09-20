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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.List;
import java.util.UUID;

import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class JdbcPatAuthorizationService implements PatAuthorizationService {

	private static final String COLUMN_NAMES = "id, "
			+ "name, "
			+ "description, "
			+ "token, "
			+ "principal, "
			+ "scopes, "
			+ "issued_at, "
			+ "expires_at, "
			+ "not_before";

	private static final String TABLE_NAME = "pat_authorizations";

	private static final String LOAD_PAT_AUTHORIZATION_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
			+ " WHERE ";

	private static final String INSERT_PAT_AUTHORIZATION_SQL = "INSERT INTO " + TABLE_NAME
			+ "(" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

	private static final String DELETE_PAT_AUTHORIZATION_SQL = "DELETE FROM " + TABLE_NAME
			+ " WHERE ";

	private final JdbcOperations jdbcOperations;

	private PatAuthorizationRowMapper patAuthorizationRowMapper;

	public JdbcPatAuthorizationService(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.patAuthorizationRowMapper = new PatAuthorizationRowMapper();
	}

	@Override
	public void save(PatAuthorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		insertPatAuthorization(authorization);
	}

	private void insertPatAuthorization(PatAuthorization authorization) {
		List<SqlParameterValue> parameters = this.patAuthorizationRowMapper.getSqlParameterValues(authorization);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(INSERT_PAT_AUTHORIZATION_SQL, pss);
	}

	@Override
	public void remove(PatAuthorization authorization) {
		deleteBy("token = ?", authorization.getToken());
	}

	private void deleteBy(String filter, Object... args) {
		this.jdbcOperations.update(DELETE_PAT_AUTHORIZATION_SQL + filter, args);
	}

	@Override
	public PatAuthorization find(String token) {
		return findBy("token = ?", token);
	}

	@Override
	public List<PatAuthorization> findByPrincipal(String principal) {
		return findAllBy("principal = ?", principal);
	}

	@Override
	public PatAuthorization findById(String id) {
		return findBy("id = ?", id);
	}

	private PatAuthorization findBy(String filter, Object... args) {
		List<PatAuthorization> result = this.jdbcOperations.query(LOAD_PAT_AUTHORIZATION_SQL + filter,
				this.patAuthorizationRowMapper, args);
		return !result.isEmpty() ? result.get(0) : null;
	}

	private List<PatAuthorization> findAllBy(String filter, Object... args) {
		List<PatAuthorization> result = this.jdbcOperations.query(LOAD_PAT_AUTHORIZATION_SQL + filter,
				this.patAuthorizationRowMapper, args);
		return result;
	}

	protected final JdbcOperations getJdbcOperations() {
		return this.jdbcOperations;
	}

	protected final RowMapper<PatAuthorization> getPatAuthorizationRowMapper() {
		return this.patAuthorizationRowMapper;
	}

	public static class PatAuthorizationRowMapper implements RowMapper<PatAuthorization> {

		@Override
		public PatAuthorization mapRow(ResultSet rs, int rowNum) throws SQLException {
			String id =  rs.getString("id");
			String name = rs.getString("name");
			String description = rs.getString("description");
			String token = rs.getString("token");
			String principal = rs.getString("principal");
			String scopes = rs.getString("scopes");
			Timestamp issuedAt = rs.getTimestamp("issued_at");
			Timestamp expiresAt = rs.getTimestamp("expires_at");
			Timestamp notBefore = rs.getTimestamp("not_before");

			return PatAuthorization.builder().id(id).name(name).description(description).principal(principal)
					.scopes(StringUtils.commaDelimitedListToSet(scopes))
					.token(token).issuedAt(issuedAt.toInstant()).expiresAt(expiresAt.toInstant())
					.notBefore(notBefore.toInstant()).build();
		}

		public List<SqlParameterValue> getSqlParameterValues(PatAuthorization authorization) {
			return List.of(
				new SqlParameterValue(Types.VARCHAR, StringUtils.hasText(authorization.getId()) ? authorization.getId() : UUID.randomUUID().toString()),
				new SqlParameterValue(Types.VARCHAR, authorization.getName()),
				new SqlParameterValue(Types.VARCHAR, authorization.getDescription()),
				new SqlParameterValue(Types.VARCHAR, authorization.getToken()),
				new SqlParameterValue(Types.VARCHAR, authorization.getPrincipal()),
				new SqlParameterValue(Types.VARCHAR, StringUtils.collectionToCommaDelimitedString(authorization.getScopes())),
				new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(authorization.getIssuedAt())),
				new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(authorization.getExpiresAt())),
				new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(authorization.getNotBefore()))
			);
		}
	}

}
