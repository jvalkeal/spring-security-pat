package com.github.jvalkeal.secpat.common;

import javax.sql.DataSource;

import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;

import com.github.jvalkeal.secpat.pat.authorization.JdbcPatAuthorizationService;
import com.github.jvalkeal.secpat.pat.authorization.PatAuthorizationService;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(DataSourceProperties.class)
@Profile("postgres")
public class CommonJdbcConfiguration {

	private final DataSourceProperties properties;

	public CommonJdbcConfiguration(DataSourceProperties properties) {
		this.properties = properties;
	}

	@Bean
	public DataSource getDataSource() {
		return DataSourceBuilder.create()
		  .driverClassName(properties.getDriverClassName())
		  .url(properties.getUrl())
		  .username(properties.getUsername())
		  .password(properties.getPassword())
		  .build();
	}


	@Bean
	public PatAuthorizationService jdbcPatAuthorizationService(JdbcOperations jdbcOperations) {
		return new JdbcPatAuthorizationService(jdbcOperations);
	}

}
