package io.mosip.registration.processor.stages.legacy.data.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class Fingerprint {

	@XmlElement(name = "position")
	 private String position;

	@XmlElement(name = "wsq")
	private String wsq;
}
