package io.mosip.registration.processor.core.exception;

import io.mosip.kernel.core.exception.BaseCheckedException;

public class DataMigrationException extends BaseCheckedException {

	public DataMigrationException(String errorCode, String message) {
        super(errorCode, message);
    }

	public DataMigrationException(String errorCode, String message, Throwable t) {
        super(errorCode, message, t);
    }
}
