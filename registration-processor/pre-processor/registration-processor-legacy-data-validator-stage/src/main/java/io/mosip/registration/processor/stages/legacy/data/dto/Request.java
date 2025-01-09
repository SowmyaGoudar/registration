package io.mosip.registration.processor.stages.legacy.data.dto;

import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;


@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class Request {
	
	@XmlElement(name = "fingerprints")
	List<Fingerprint> fingerprints;

	@XmlElement(name = "nationalId")
	private String nationalId;

}