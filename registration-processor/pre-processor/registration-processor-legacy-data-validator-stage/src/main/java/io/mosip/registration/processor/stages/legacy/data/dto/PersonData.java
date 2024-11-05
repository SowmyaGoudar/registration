package io.mosip.registration.processor.stages.legacy.data.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class PersonData {
	@XmlElement(name = "transactionStatus")
	private TransactionStatus transactionStatus;

	@XmlElement(name = "nationalId")
	private String nationalId;

	@XmlElement(name = "surname")
	private String surname;

	@XmlElement(name = "givenNames")
	private String givenNames;

	@XmlElement(name = "maidenNames")
	private String maidenNames;

	@XmlElement(name = "previousSurnames")
	private String previousSurnames;

	@XmlElement(name = "dateOfBirth")
	private String dateOfBirth;

	@XmlElement(name = "dateOfBirthEstimated")
	private boolean dateOfBirthEstimated;

	@XmlElement(name = "gender")
	private String gender;

	@XmlElement(name = "nationality")
	private String nationality;

	@XmlElement(name = "livingStatus")
	private String livingStatus;

	@XmlElement(name = "photo")
	private String photo;

	// Getters and Setters
	// (You can generate these using your IDE)
}