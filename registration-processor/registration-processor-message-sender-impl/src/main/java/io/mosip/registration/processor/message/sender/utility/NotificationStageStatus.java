package io.mosip.registration.processor.message.sender.utility;

public enum NotificationStageStatus {
	
	CMD_VALIDATION_FAILED,
	
	OPERATOR_VALIDATION_FAILED,
	
	SUPERVISOR_VALIDATION_FAILED,
	
	INTRODUCER_VALIDATION_FAILED,
	
	VALIDATE_PACKET_FAILED,
	
	MANUAL_VERIFICATION_FAILED,
	
	UIN_GENERATOR_SUCCESS,
	
	BIOGRAPHIC_VERIFICATION_FAILED,
	
	DEMOGRAPHIC_VERIFICATION_FAILED,
	
	UIN_GENERATOR_PROCESSED,

	QUALITY_CHECK_FAILED,

	VALIDATE_PACKET_REJECTED,

	BIOMETRIC_AUTHENTICATION_FAILED, 
	
	PACKET_REJECTED,
	
	MVS_PACKET_REJECTED,

	PACKET_FAILED,

	ON_DEMAND_MIGRATION_FAILED,

	ON_DEMAND_MIGRATION_REJECTED;

}
