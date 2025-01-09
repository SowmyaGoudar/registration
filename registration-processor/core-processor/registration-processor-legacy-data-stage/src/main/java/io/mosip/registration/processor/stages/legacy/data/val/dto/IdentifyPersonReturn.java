package io.mosip.registration.processor.stages.legacy.data.val.dto;

import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class IdentifyPersonReturn {

	@XmlElement(name = "transactionStatus")
	private TransactionStatus transactionStatus;

	@XmlElement(name = "persons")
	private List<Person> persons;

}
