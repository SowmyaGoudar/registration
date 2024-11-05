package io.mosip.registration.processor.stages.legacy.data.stage.exception;

import io.mosip.kernel.core.exception.BaseCheckedException;

public class PacketOnHoldException extends BaseCheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new PacketOnHoldException .
	 */
	public PacketOnHoldException() {
		super();
	}

	/**
	 * 
	 * @param message
	 */
	public PacketOnHoldException(String code,String message) {
		super(code, message);
	}
}
