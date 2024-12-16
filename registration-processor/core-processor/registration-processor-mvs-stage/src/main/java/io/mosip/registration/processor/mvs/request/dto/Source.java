package io.mosip.registration.processor.mvs.request.dto;

import java.util.List;

import lombok.Data;

@Data
public class Source {
	public String attribute;

	public List<Filter> filter;
}
