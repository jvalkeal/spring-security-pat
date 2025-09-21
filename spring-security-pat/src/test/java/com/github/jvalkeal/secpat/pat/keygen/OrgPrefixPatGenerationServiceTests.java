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
package com.github.jvalkeal.secpat.pat.keygen;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class OrgPrefixPatGenerationServiceTests {

	private OrgPrefixPatGenerationService service;

	@BeforeEach
	void setup() {
		this.service = new OrgPrefixPatGenerationService("org", "type", 51);
	}

	@Test
	void canGenerateAndValidateToken() {
		String token = service.generate(null);
		assertThat(token).isNotNull();
		assertThat(service.validate(token)).isTrue();
	}

	@Test
	void willNotValidateNullToken() {
		assertThat(service.validate(null)).isFalse();
	}

	@Test
	void willNotValidateKnownInvalidTokens() {
		assertThat(service.validate("")).isFalse();
		assertThat(service.validate("foobar")).isFalse();
		assertThat(service.validate("org_type_3lModz")).isFalse();
		assertThat(service.validate("org_type_3lModz_")).isFalse();
		assertThat(service.validate("org_type_3lModz_x")).isFalse();
	}

	@Test
	void willValidatePossiblyValidTokens() {
		assertThat(service.validate("org_type_3lModz_IvL5Cyh2SR1tXrbOlfPqPU01JIgjETjNY7iqXdEJdcUto4n3BpZ")).isTrue();
	}

}
