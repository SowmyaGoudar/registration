package io.mosip.registration.processor.stages.legacy.data.val;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import io.mosip.registration.processor.stages.legacy.data.val.stage.LegacyDataStage;



public class LegacyDataApp {
	/**
	 * The main method.
	 *
	 * @param args
	 */
	public static void main(String[] args) {
		AnnotationConfigApplicationContext configApplicationContext = new AnnotationConfigApplicationContext();
		configApplicationContext.scan("io.mosip.registration.processor.core.config",
				"io.mosip.registration.processor.stages.legacy.data.val",
				"io.mosip.registration.processor.packet.manager.config",
				"io.mosip.kernel.packetmanager.config",
				"io.mosip.registration.processor.packet.storage.config",
				"io.mosip.registration.processor.status.config", "io.mosip.registration.processor.rest.client.config",
				"io.mosip.registration.processor.core.kernel.beans");
		configApplicationContext.refresh();

		LegacyDataStage legacyDataStage = configApplicationContext.getBean(LegacyDataStage.class);

		legacyDataStage.deployVerticle();
	}

}
