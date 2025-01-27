package io.mosip.registration.processor.transaction.api.scheduler;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.packet.storage.utils.PasswordChangeUtility;

@Component
@EnableScheduling
public class PasswordChangeScheduler {

	private static Logger regProcLogger = RegProcessorLogger.getLogger(PasswordChangeScheduler.class);

	@Autowired
	private PasswordChangeUtility passwordChangeUtility;

	@Value("${mosip.registration.processor.passwordchange.scheduler.interveldays}")
	private int days;

	private LocalDate lastExecuted;

	@PostConstruct
	public void init() {
		regProcLogger.info("Initialized with interval of " + days + " days");
		if (lastExecuted == null) {
			this.lastExecuted = LocalDate.now().minusDays(days);
			try{
				regProcLogger.info("PasswordChange scheduler started in postconstructor");
				passwordChangeUtility.updatePassword();
				regProcLogger.info("PasswordChange scheduler ended in postconstructor");
			} catch (Exception e) {
				regProcLogger.error("Error while processing password change scheduler ", e);
			}
		}
		regProcLogger.info("Last executed date: " + lastExecuted);
	}

	@Scheduled(cron = "${mosip.registration.processor.passwordchange.scheduler.cronexpression}")
	public void scheduleTask() {
		try {
			regProcLogger.info("PasswordChange scheduler checking days");
			long daysBetween = ChronoUnit.DAYS.between(lastExecuted, LocalDate.now());
			if (daysBetween >= days) {
				regProcLogger.info("PasswordChange scheduler exceededs password expiry intervel");
				regProcLogger.info("PasswordChange scheduler started");
				passwordChangeUtility.updatePassword();
				lastExecuted = LocalDate.now();
				regProcLogger.info("PasswordChange scheduler ended");
			}
			regProcLogger.info("PasswordChange scheduler checking days done");

		} catch (Exception e) {
			regProcLogger.error("Error while processing password change scheduler ", e);
		}

	}
}
