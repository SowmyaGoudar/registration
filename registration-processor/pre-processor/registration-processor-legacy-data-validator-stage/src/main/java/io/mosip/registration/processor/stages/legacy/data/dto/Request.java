package io.mosip.registration.processor.stages.legacy.data.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

//Request class
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class Request {
	@XmlElement(name = "nationalId")
	private String nationalId;

	// Getters and setters
	public String getNationalId() {
		return nationalId;
	}

	public void setNationalId(String nationalId) {
		this.nationalId = nationalId;
	}
}