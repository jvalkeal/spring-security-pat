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

package com.github.jvalkeal.secpat.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

public class PatPropertiesTests {

	private final PatProperties pat = new PatProperties();

	private Binder binder;

	private final MapConfigurationPropertySource source = new MapConfigurationPropertySource();

	@BeforeEach
	void setUp() {
		this.binder = new Binder(this.source);
	}

	@Test
	void onDefaultEmptyUsersList() {
		this.binder.bind("spring.security.pat", Bindable.ofInstance(this.pat));
		assertThat(this.pat.getPats()).isEmpty();
	}

	@Test
	void bindUserPrincipal() {
		this.source.put("spring.security.pat.pats[0].principal", "user1");
		this.binder.bind("spring.security.pat", Bindable.ofInstance(this.pat));
		assertThat(this.pat.getPats()).hasSize(1);
		assertThat(this.pat.getPats().get(0).getPrincipal()).isEqualTo("user1");
		assertThat(this.pat.getPats().get(0).getScopes()).isEmpty();
	}

	@Test
	void bindUserInstantFields() {
		this.source.put("spring.security.pat.pats[0].issued-at", "0");
		this.source.put("spring.security.pat.pats[0].expires-at", "0");
		this.source.put("spring.security.pat.pats[0].not-before", "0");
		this.binder.bind("spring.security.pat", Bindable.ofInstance(this.pat));
		assertThat(this.pat.getPats()).hasSize(1);
		assertThat(this.pat.getPats().get(0).getIssuedAt()).isNotNull();
		assertThat(this.pat.getPats().get(0).getExpiresAt()).isNotNull();
		assertThat(this.pat.getPats().get(0).getNotBefore()).isNotNull();
		assertThat(this.pat.getPats().get(0).getIssuedAt()).isEqualTo(Instant.ofEpochMilli(0));
		assertThat(this.pat.getPats().get(0).getExpiresAt()).isEqualTo(Instant.ofEpochMilli(0));
		assertThat(this.pat.getPats().get(0).getNotBefore()).isEqualTo(Instant.ofEpochMilli(0));
	}

	@Test
	void bindUserScopes() {
		this.source.put("spring.security.pat.pats[0].scopes[0]", "scope1");
		this.binder.bind("spring.security.pat", Bindable.ofInstance(this.pat));
		assertThat(this.pat.getPats()).hasSize(1);
		assertThat(this.pat.getPats().get(0).getScopes()).containsExactly("scope1");
	}

}
