package io.mosip.registration.processor.stages.legacy.data.stage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.processor.core.abstractverticle.MessageBusAddress;
import io.mosip.registration.processor.core.abstractverticle.MessageDTO;
import io.mosip.registration.processor.core.abstractverticle.MosipEventBus;
import io.mosip.registration.processor.core.abstractverticle.MosipRouter;
import io.mosip.registration.processor.core.abstractverticle.MosipVerticleAPIManager;
import io.mosip.registration.processor.core.constant.LoggerFileConstant;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;



@Component
@Configuration
@ComponentScan(basePackages = { "${mosip.auth.adapter.impl.basepackage}",
		"io.mosip.registration.processor.core.config",
		"io.mosip.registration.processor.stages.legacy.data",
		"io.mosip.registration.processor.stages.config", 
		"io.mosip.registrationprocessor.stages.config", 
		"io.mosip.registration.processor.status.config",
		"io.mosip.registration.processor.rest.client.config", 
		"io.mosip.registration.processor.packet.storage.config",
		"io.mosip.registration.processor.packet.manager.config", 
		"io.mosip.registration.processor.core.kernel.beans" })
public class LegacyDataValidatorStage extends MosipVerticleAPIManager {
	
	private static final String STAGE_PROPERTY_PREFIX = "mosip.regproc.legacy.data.validator.";

	/** The reg proc logger. */
	private static Logger regProcLogger = RegProcessorLogger.getLogger(LegacyDataValidatorStage.class);

	/** The cluster url. */
	@Value("${vertx.cluster.configuration}")
	private String clusterManagerUrl;

	/** worker pool size. */
	@Value("${worker.pool.size}")
	private Integer workerPoolSize;

	/** After this time intervel, message should be considered as expired (In seconds). */
	@Value("${mosip.regproc.legacy.data.validator.message.expiry-time-limit}")
	private Long messageExpiryTimeLimit;

	/**
	 * The mosip event bus.
	 */
	private MosipEventBus mosipEventBus;
	
	@Autowired
	LegacyDataValidateProcessor legacyDataValidateProcessor;


	/** Mosip router for APIs */
	@Autowired
	MosipRouter router;
	
	@Override
	protected String getPropertyPrefix() {
		return STAGE_PROPERTY_PREFIX;
	}

	/**
	 * Deploy verticle.
	 */
	public void deployVerticle() {
		this.mosipEventBus = this.getEventBus(this, clusterManagerUrl, workerPoolSize);
		this.consumeAndSend(mosipEventBus, MessageBusAddress.LEGACY_DATA_VALIDATOR_IN,
				MessageBusAddress.LEGACY_DATA_VALIDATOR_OUT, messageExpiryTimeLimit);

	}

	@Override
	public void start(){
		router.setRoute(this.postUrl(getVertx(), MessageBusAddress.LEGACY_DATA_VALIDATOR_IN,
				MessageBusAddress.LEGACY_DATA_VALIDATOR_OUT));
		this.createServer(router.getRouter(), getPort());
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * io.mosip.registration.processor.core.spi.eventbus.EventBusManager#process(
	 * java.lang.Object)
	 */
	@Override
	public MessageDTO process(MessageDTO messageDTO) {
		regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(), "",
				"LegacyDataValidatorStage::process()::entry");

		messageDTO.setMessageBusAddress(MessageBusAddress.LEGACY_DATA_VALIDATOR_IN);
		messageDTO.setInternalError(Boolean.FALSE);
		messageDTO.setIsValid(Boolean.FALSE);
		messageDTO = legacyDataValidateProcessor.process(messageDTO, getStageName());

		regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
				"LegacyDataValidatorStage::process()::exit", messageDTO.toString());

		return messageDTO;
	}
	/**
	 * Gets the stage name.
	 *
	 * @return the stage name
	 */
	protected String getStageName() {
		return ClassUtils.getUserClass(this.getClass()).getSimpleName();
	}
}
