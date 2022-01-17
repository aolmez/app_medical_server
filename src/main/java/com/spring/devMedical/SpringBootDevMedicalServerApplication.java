package com.spring.devMedical;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringBootDevMedicalServerApplication {

	@Value("${spring.server.port}")
	private static long port = 8080L;

	public static void main(String[] args) {
		SpringApplication.run(SpringBootDevMedicalServerApplication.class, args);
		System.out.println(String.format("************Server started in port %s***********", port));
	}

}
