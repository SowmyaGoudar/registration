package io.mosip.registration.processor.stages.legacy.data.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.mosip.registration.processor.stages.legacy.data.stage.LegacyDataValidateProcessor;

@Configuration
public class LegacyDataConfig {

	@Bean
	public LegacyDataValidateProcessor getLegacyDataValidateProcessor() {
		return new LegacyDataValidateProcessor();
	}
}
