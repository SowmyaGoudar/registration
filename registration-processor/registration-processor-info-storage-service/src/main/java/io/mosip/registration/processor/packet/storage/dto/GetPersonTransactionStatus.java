package io.mosip.registration.processor.packet.storage.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class GetPersonTransactionStatus {
	@XmlElement(name = "transactionStatus")
	private String transactionStatus;

	@XmlElement(name = "error")
	private Error error;

	@XmlElement(name = "passwordDaysLeft")
	private int passwordDaysLeft;

	@XmlElement(name = "executionCost")
	private double executionCost;


}