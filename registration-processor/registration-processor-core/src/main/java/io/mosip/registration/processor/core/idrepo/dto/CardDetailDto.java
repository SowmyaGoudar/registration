package io.mosip.registration.processor.core.idrepo.dto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CardDetailDto {

	private String cardNumber;
	private String dateOfIssuance;
	private String dateOfExpiry;
}
