package io.mosip.registration.processor.mvs.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.mosip.registration.processor.mvs.exception.handler.MVSExceptionHandler;
import io.mosip.registration.processor.mvs.service.MVSService;
import io.mosip.registration.processor.mvs.service.impl.MVSServiceImpl;
import io.mosip.registration.processor.mvs.util.MVSRequestValidator;
import io.mosip.registration.processor.mvs.util.SaveVerificationRecordUtility;

@Configuration
public class VerificationConfigBean {
	
	
	@Bean
    MVSService getManualVerificationService() {
		return new MVSServiceImpl();
	}

	@Bean
	MVSRequestValidator getManualVerificationRequestValidator() {
		return new MVSRequestValidator();
	}
	
	@Bean
    MVSExceptionHandler getManualVerificationExceptionHandler() {
		return new MVSExceptionHandler();
	}
	
	@Bean
	SaveVerificationRecordUtility getsSaveVerificationRecordUtility() {
		return new SaveVerificationRecordUtility();
	}

}