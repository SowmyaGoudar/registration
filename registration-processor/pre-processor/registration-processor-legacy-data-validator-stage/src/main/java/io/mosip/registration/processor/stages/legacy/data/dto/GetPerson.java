package io.mosip.registration.processor.stages.legacy.data.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;

//GetPerson class
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class GetPerson {
	@XmlElement(name = "request")
	private Request request;
}