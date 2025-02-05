package io.mosip.registration.processor.stages.utils;

public enum NotificationTemplateType {

	/** The new registration. */
	NEW_REG,

	/** The uin update. */
	UIN_UPDATE,
	
	/** The uin renewal. */
	UIN_RENEWAL,
	
	/** The Lost UIN. */
	LOST_UIN,

	/** Re-print uin. */
	REPRINT_UIN,
	
	/** The activate uin. */
	ACTIVATE,
	
	/** The de-activate uin. */
	DEACTIVATE,
	
	/** Res Update. */
	RES_UPDATE,
	
	/** The technical issue. */
	TECHNICAL_ISSUE,
	
	SUP_REJECT,

	GET_FIRSTID
	
}
