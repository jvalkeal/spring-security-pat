package com.github.jvalkeal.secpat.apiserver;

import java.util.concurrent.TimeUnit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ApiServerApplication {

	public static void main(String[] args) throws InterruptedException {
		// sleep to give time for idserver to start
		TimeUnit.SECONDS.sleep(3);
		SpringApplication.run(ApiServerApplication.class, args);
	}

}
