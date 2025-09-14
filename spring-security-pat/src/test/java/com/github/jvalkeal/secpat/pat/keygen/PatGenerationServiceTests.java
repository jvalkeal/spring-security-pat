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

import org.junit.jupiter.api.Test;

class PatGenerationServiceTests {

	@Test
	void testGeneration() {
		// PatGenerationService service = new CustomPatGenerationService();
		// assertThat(service.generate("user1")).isEqualTo("pat1111");
		PatService service = new CustomPatGenerationService();
		assertThat(service.generator().apply("user1")).isEqualTo("pat1111");
	}

	static class CustomPatGenerationService implements PatGenerationService, PatService {

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

		@Override
		public String generate(Object source) {
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
			throw new IllegalArgumentException("Unsupported source");
		}

		@Override
		public boolean validate(String pat) {
			return pat != null && pat.startsWith("pat");
		}

	}

}
