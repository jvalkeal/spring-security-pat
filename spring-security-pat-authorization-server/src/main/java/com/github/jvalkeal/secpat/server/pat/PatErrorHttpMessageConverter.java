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

package com.github.jvalkeal.secpat.server.pat;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.github.jvalkeal.secpat.pat.PatError;

/**
 * A {@link HttpMessageConverter} for an {@link PathError}.
 *
 * @see AbstractHttpMessageConverter
 * @see PatError
 */
public class PatErrorHttpMessageConverter extends AbstractHttpMessageConverter<PatError> {

	private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	protected Converter<Map<String, String>, PatError> errorConverter = new PatErrorConverter();

	protected Converter<PatError, Map<String, String>> errorParametersConverter = new PatErrorParametersConverter();

	public PatErrorHttpMessageConverter() {
		super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return PatError.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected PatError readInternal(Class<? extends PatError> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			// gh-8157: Parse parameter values as Object in order to handle potential JSON
			// Object and then convert values to String
			Map<String, Object> errorParameters = (Map<String, Object>) this.jsonMessageConverter
				.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.errorConverter.convert(errorParameters.entrySet()
				.stream()
				.collect(Collectors.toMap(Map.Entry::getKey, (entry) -> String.valueOf(entry.getValue()))));
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the Pat Error: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(PatError patError, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, String> errorParameters = this.errorParametersConverter.convert(patError);
			this.jsonMessageConverter.write(errorParameters, STRING_OBJECT_MAP.getType(), MediaType.APPLICATION_JSON,
					outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the Pat Error: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the Pat Error parameters to an
	 * {@link PatError}.
	 * @param errorConverter the {@link Converter} used for converting to an
	 * {@link PatError}
	 */
	public final void setErrorConverter(Converter<Map<String, String>, PatError> errorConverter) {
		Assert.notNull(errorConverter, "errorConverter cannot be null");
		this.errorConverter = errorConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link PatError} to a
	 * {@code Map} representation of the Pat Error parameters.
	 * @param errorParametersConverter the {@link Converter} used for converting to a
	 * {@code Map} representation of the Error parameters
	 */
	public final void setErrorParametersConverter(
			Converter<PatError, Map<String, String>> errorParametersConverter) {
		Assert.notNull(errorParametersConverter, "errorParametersConverter cannot be null");
		this.errorParametersConverter = errorParametersConverter;
	}

	/**
	 * A {@link Converter} that converts the provided Pat Error parameters to an
	 * {@link PatError}.
	 */
	private static class PatErrorConverter implements Converter<Map<String, String>, PatError> {

		@Override
		public PatError convert(Map<String, String> parameters) {
			String errorCode = parameters.get(PatParameterNames.ERROR);
			String errorDescription = parameters.get(PatParameterNames.ERROR_DESCRIPTION);
			return new PatError(errorCode, errorDescription);
		}

	}

	/**
	 * A {@link Converter} that converts the provided {@link PatError} to a {@code Map}
	 * representation of Pat Error parameters.
	 */
	private static class PatErrorParametersConverter implements Converter<PatError, Map<String, String>> {

		@Override
		public Map<String, String> convert(PatError patError) {
			Map<String, String> parameters = new HashMap<>();
			parameters.put(PatParameterNames.ERROR, patError.getErrorCode());
			if (StringUtils.hasText(patError.getDescription())) {
				parameters.put(PatParameterNames.ERROR_DESCRIPTION, patError.getDescription());
			}
			return parameters;
		}

	}

}
