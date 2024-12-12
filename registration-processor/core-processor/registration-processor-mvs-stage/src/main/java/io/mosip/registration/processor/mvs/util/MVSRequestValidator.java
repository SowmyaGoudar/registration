package io.mosip.registration.processor.mvs.util;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TimeZone;

import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.format.datetime.joda.DateTimeFormatterFactory;
import org.springframework.stereotype.Component;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.processor.core.exception.util.PlatformErrorMessages;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.mvs.constants.VerificationConstants;
import io.mosip.registration.processor.mvs.exception.ManualVerificationAppException;
import io.mosip.registration.processor.mvs.exception.ManualVerificationValidationException;
import io.vertx.core.json.JsonObject;

/**
 * The Class ManualVerificationRequestValidator.
 * @author Rishabh Keshari
 */
@Component
public class MVSRequestValidator{


	/** The mosip logger. */
	Logger regProcLogger = RegProcessorLogger.getLogger(MVSRequestValidator.class);


	/** The env. */
	@Autowired
	private Environment env;

	/** The id. */
	//	@Resource
	private Map<String, String> id=new HashMap<>();
	
	/** The grace period. */
	@Value("${mosip.registration.processor.grace.period}")
	private int gracePeriod;

	/**
	 * Validate.
	 *
	 * @param obj the obj
	 * @param serviceId the service id
	 * @throws ManualVerificationAppException the manual verification app exception
	 */
	public void validate(JsonObject obj,String serviceId){
		id.put("manual", serviceId);
		validateId(obj.getString("id"));
		validateVersion(obj.getString("version"));
		validateReqTime(obj.getString("requesttime"));
	}





	/**
	 * Validate id.
	 *
	 * @param id            the id
	 * @throws ManualVerificationAppException the manual verification app exception
	 */
	private void validateId(String id) {
		ManualVerificationValidationException exception = new ManualVerificationValidationException();
		
		if (Objects.isNull(id)) {
			
			throw new ManualVerificationAppException(PlatformErrorMessages.RPR_MVS_MISSING_INPUT_PARAMETER_ID,exception);
		} else if (!this.id.containsValue(id)) {

			throw new ManualVerificationAppException(PlatformErrorMessages.RPR_MVS_INVALID_INPUT_PARAMETER_ID,exception);
		
		}
	}

	/**
	 * Validate ver.
	 *
	 * @param ver            the ver
	 * @throws ManualVerificationAppException the manual verification app exception
	 */
	private void validateVersion(String ver){
		ManualVerificationValidationException exception = new ManualVerificationValidationException();
		
		if (Objects.isNull(ver)) {
			throw new ManualVerificationAppException(PlatformErrorMessages.RPR_MVS_MISSING_INPUT_PARAMETER_VERSION,exception);
			
		} else if ((!VerificationConstants.verPattern.matcher(ver).matches())) {
			
			throw new ManualVerificationAppException(PlatformErrorMessages.RPR_MVS_INVALID_INPUT_PARAMETER_VERSION,exception);
			}
	}


	/**
	 * Validate req time.
	 *
	 * @param timestamp            the timestamp
	 * @throws ManualVerificationAppException the manual verification app exception
	 */
	private void validateReqTime(String timestamp){
		ManualVerificationValidationException exception = new ManualVerificationValidationException();
		
		if (Objects.isNull(timestamp)) {
			throw new ManualVerificationAppException(PlatformErrorMessages.RPR_MVS_MISSING_INPUT_PARAMETER_TIMESTAMP,exception);
			
			} else {
			try {
				if (Objects.nonNull(env.getProperty(VerificationConstants.DATETIME_PATTERN))) {
					DateTimeFormatterFactory timestampFormat = new DateTimeFormatterFactory(
							env.getProperty(VerificationConstants.DATETIME_PATTERN));
					timestampFormat.setTimeZone(TimeZone.getTimeZone(env.getProperty(VerificationConstants.DATETIME_TIMEZONE)));
					if (!(DateTime.parse(timestamp, timestampFormat.createDateTimeFormatter())
							.isAfter(new DateTime().minusSeconds(gracePeriod))
							&& DateTime.parse(timestamp, timestampFormat.createDateTimeFormatter())
									.isBefore(new DateTime().plusSeconds(gracePeriod)))) {
						
						regProcLogger.error(VerificationConstants.MAN_VERI_SERVICE, "ManReqRequestValidator", "validateReqTime",
								"\n" + PlatformErrorMessages.RPR_MVS_INVALID_INPUT_PARAMETER_TIMESTAMP.getMessage());
						
					throw new ManualVerificationAppException(PlatformErrorMessages.RPR_MVS_INVALID_INPUT_PARAMETER_TIMESTAMP,exception);
							}

				}
			} catch (IllegalArgumentException e) {
				regProcLogger.error(VerificationConstants.MAN_VERI_SERVICE, "ManReqRequestValidator", "validateReqTime",
						"\n" + ExceptionUtils.getStackTrace(e));
				throw new ManualVerificationAppException(PlatformErrorMessages.RPR_MVS_INVALID_INPUT_PARAMETER_TIMESTAMP,exception);
				}
		}
	}


}
