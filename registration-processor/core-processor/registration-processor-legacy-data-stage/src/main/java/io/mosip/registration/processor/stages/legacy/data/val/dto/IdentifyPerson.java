package io.mosip.registration.processor.stages.legacy.data.val.dto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import lombok.Data;


@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class IdentifyPerson {
	@XmlElement(name = "request")
	private Request request;
}