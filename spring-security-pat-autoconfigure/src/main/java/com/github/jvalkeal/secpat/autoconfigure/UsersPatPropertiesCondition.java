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

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

import com.github.jvalkeal.secpat.autoconfigure.PatProperties.Pat;

/**
 * Condition that matches if any {@code spring.security.pat.pats} properties are
 * defined.
 *
 * @author Janne Valkealahti
 */
public class UsersPatPropertiesCondition extends SpringBootCondition {

	private static final Bindable<List<Pat>> STRING_REGISTRATION_LIST = Bindable.listOf(PatProperties.Pat.class);

	@Override
	public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
		ConditionMessage.Builder message = ConditionMessage.forCondition("Security Pat pats Configured Condition");
		List<Pat> pats = getPats(context.getEnvironment());
		if (!pats.isEmpty()) {
			return ConditionOutcome.match(message.foundExactly("registered pats " + pats
				.stream()
				.map(Pat::getPrincipal)
				.collect(Collectors.joining(", "))));
		}
		return ConditionOutcome.noMatch(message.notAvailable("registered pats"));
	}

	private List<Pat> getPats(Environment environment) {
		return Binder.get(environment)
			.bind("spring.security.pat.pats", STRING_REGISTRATION_LIST)
			.orElse(Collections.emptyList());
	}

}
