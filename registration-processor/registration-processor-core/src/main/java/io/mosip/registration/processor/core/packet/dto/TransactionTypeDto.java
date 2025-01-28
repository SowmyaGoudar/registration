package io.mosip.registration.processor.core.packet.dto;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class TransactionTypeDto {


	private static final long serialVersionUID = 1L;

	private String code;

	private String langCode;

	private String description;

	private Boolean isActive;


	private Boolean isDeleted;

	private String crBy;

	private LocalDateTime crDtimes;


	private LocalDateTime delDtimes;


	private String updBy;

	private LocalDateTime updDtimes;

}
