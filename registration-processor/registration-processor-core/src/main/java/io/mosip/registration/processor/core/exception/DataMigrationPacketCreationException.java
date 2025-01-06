package io.mosip.registration.processor.core.exception;

import io.mosip.kernel.core.exception.BaseCheckedException;

public class DataMigrationPacketCreationException  extends BaseCheckedException {

	public DataMigrationPacketCreationException(String errorCode, String message) {
        super(errorCode, message);
    }

	public DataMigrationPacketCreationException(String errorCode, String message, Throwable t) {
        super(errorCode, message, t);
    }
}
