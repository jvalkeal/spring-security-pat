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

package com.github.jvalkeal.secpat.pat.config;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Base configurer for a PAT component.
 *
 * @author Janne Valkealahti
 */
public abstract class AbstractPatConfigurer {

	private final ObjectPostProcessor<Object> objectPostProcessor;

	protected AbstractPatConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	public abstract void init(HttpSecurity httpSecurity);

	public abstract void configure(HttpSecurity httpSecurity);

	public abstract RequestMatcher getRequestMatcher();

	protected final <T> T postProcess(T object) {
		return (T) this.objectPostProcessor.postProcess(object);
	}

	protected final ObjectPostProcessor<Object> getObjectPostProcessor() {
		return this.objectPostProcessor;
	}

}
