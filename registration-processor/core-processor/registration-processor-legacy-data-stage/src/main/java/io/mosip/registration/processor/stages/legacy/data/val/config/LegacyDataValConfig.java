package io.mosip.registration.processor.stages.legacy.data.val.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.mosip.registration.processor.stages.legacy.data.val.stage.LegacyDataProcessor;

@Configuration
public class LegacyDataValConfig {

	@Bean
	public LegacyDataProcessor getLegacyDataProcessor() {
		return new LegacyDataProcessor();
	}

}
