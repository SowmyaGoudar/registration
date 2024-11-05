package io.mosip.registration.processor.stages.legacy.data.stage;

import java.io.IOException;
import java.io.StringReader;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.exception.JsonProcessingException;
import io.mosip.registration.processor.core.code.ApiName;
import io.mosip.registration.processor.core.constant.LoggerFileConstant;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;
import io.mosip.registration.processor.core.exception.PacketManagerException;
import io.mosip.registration.processor.core.exception.ValidationFailedException;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.core.util.RegistrationExceptionMapperUtil;
import io.mosip.registration.processor.packet.storage.utils.PriorityBasedPacketManagerService;
import io.mosip.registration.processor.packet.storage.utils.Utilities;
import io.mosip.registration.processor.stages.legacy.data.dto.Body;
import io.mosip.registration.processor.stages.legacy.data.dto.Envelope;
import io.mosip.registration.processor.stages.legacy.data.dto.GetPerson;
import io.mosip.registration.processor.stages.legacy.data.dto.GetPersonResponse;
import io.mosip.registration.processor.stages.legacy.data.dto.Header;
import io.mosip.registration.processor.stages.legacy.data.dto.Password;
import io.mosip.registration.processor.stages.legacy.data.dto.Request;
import io.mosip.registration.processor.stages.legacy.data.dto.TransactionStatus;
import io.mosip.registration.processor.stages.legacy.data.dto.UsernameToken;
import io.mosip.registration.processor.stages.legacy.data.stage.exception.PacketOnHoldException;
import io.mosip.registration.processor.stages.legacy.data.util.LegacyDataApiUtility;
import io.mosip.registration.processor.status.code.RegistrationStatusCode;
import io.mosip.registration.processor.status.dto.InternalRegistrationStatusDto;
import io.mosip.registration.processor.status.dto.RegistrationStatusDto;
import io.mosip.registration.processor.status.service.RegistrationStatusService;

@Service
public class LegacyDataValidator {
	private static Logger regProcLogger = RegProcessorLogger.getLogger(LegacyDataValidator.class);

	public static final String INDIVIDUAL_TYPE_UIN = "UIN";

	@Autowired
	RegistrationExceptionMapperUtil registrationExceptionMapperUtil;

	@Autowired
	private PriorityBasedPacketManagerService packetManagerService;


	@Autowired
	RegistrationStatusService<String, InternalRegistrationStatusDto, RegistrationStatusDto> registrationStatusService;

	@Autowired
	ObjectMapper mapper;

	@Autowired
	private Utilities utility;
	
	@Autowired
	private LegacyDataApiUtility legacyDataApiUtility;

	@Autowired
	private RegistrationProcessorRestClientService<Object> restApi;

	@Value("${mosip.regproc.legacydata.validator.tpi.username}")
	private String username;

	@Value("${mosip.regproc.legacydata.validator.tpi.password}")
	private String password;

	public void validate(String registrationId, InternalRegistrationStatusDto registrationStatusDto)
			throws ApisResourceAccessException, PacketManagerException, JsonProcessingException, IOException,
			ValidationFailedException, PacketOnHoldException, JAXBException, NoSuchAlgorithmException {

		regProcLogger.debug("validate called for registrationId {}", registrationId);

		String NIN = "CF200721001NRA";// packetManagerService.getFieldByMappingJsonKey(registrationId,
				//MappingJsonConstants.NIN, registrationStatusDto.getRegistrationType(),
				//ProviderStageName.LEGACY_DATA_VALIDATOR);

				JSONObject jSONObject = null; // utility.getIdentityJSONObjectByHandle(NIN);
		if (jSONObject == null) {
			boolean isPresentInlegacySystem = false;
			// fetch legacy system data by calling api
			isPresentInlegacySystem = checkNINAVailableInLegacy(registrationId, NIN);
			if (isPresentInlegacySystem) {
				// check migration utlity data processed table by calling api
				boolean isPresentMigrationUtilityProcessedTable = false;
				if (isPresentMigrationUtilityProcessedTable) {

				} else {
					// Call for ondemand migration of packet by passing NIN
					throw new PacketOnHoldException(StatusUtil.PACKET_ON_HOLD_FOR_MIGRATION.getCode(),
							StatusUtil.PACKET_ON_HOLD_FOR_MIGRATION.getMessage());

				}
			} else {
				throw new ValidationFailedException(StatusUtil.LEGACY_DATA_VALIDATION_FAILED.getMessage(),
						StatusUtil.LEGACY_DATA_VALIDATION_FAILED.getCode());
			}
		}

		regProcLogger.debug("validate call ended for registrationId {}", registrationId);
	}

	private boolean checkNINAVailableInLegacy(String registrationId, String NIN)
			throws JAXBException, ApisResourceAccessException, NoSuchAlgorithmException {
		boolean isValid = false;
		Envelope requestEnvelope = createGetPersonRequest(NIN);
		String request = marshalToXml(requestEnvelope);
		String response = (String) restApi.postApi(ApiName.GETPERSONURL, "", "", request, String.class,
				MediaType.TEXT_XML);
		JAXBContext jaxbContext = JAXBContext.newInstance(Envelope.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		StringReader reader = new StringReader(response);
		Envelope responseEnvelope = (Envelope) unmarshaller.unmarshal(reader);
		GetPersonResponse getPersonResponse = responseEnvelope.getBody().getGetPersonResponse();
		TransactionStatus transactionStatus = getPersonResponse.getReturnData().getTransactionStatus();
		if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Ok")) {
			if (getPersonResponse.getReturnData().getNationalId().equals(NIN)) {
				isValid = true;
			}
		} else if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Error")) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					registrationId,
					RegistrationStatusCode.FAILED.toString() + transactionStatus.getError().getCode()
							+ transactionStatus.getError().getMessage());
		}
		return isValid;
	}

	private Envelope createGetPersonRequest(String NIN) throws NoSuchAlgorithmException {
		byte[] nonceBytes = legacyDataApiUtility.generateNonce();
		String nonce = CryptoUtil.encodeToPlainBase64(nonceBytes);

		String timestamp = legacyDataApiUtility.createTimestamp();
        byte[] createdDigestBytes = timestamp.getBytes();

		byte[] passwordHashBytes = legacyDataApiUtility.hashPassword(password);
		String passwordDigest = legacyDataApiUtility.generateDigest(nonceBytes, createdDigestBytes, passwordHashBytes);
		Envelope envelope = new Envelope();

		// Header
		Header header = new Header();
		UsernameToken token = new UsernameToken();
		token.setUsername(username);
		Password password = new Password();
		password.setType("PasswordDigest");
		password.setValue(passwordDigest);
		token.setPassword(password);
		token.setNonce(nonce);
		token.setCreated(timestamp);
		header.setUsernameToken(token);
		envelope.setHeader(header);

		// Body
		Body body = new Body();
		GetPerson getPerson = new GetPerson();
		Request request = new Request();
		request.setNationalId(NIN);
		getPerson.setRequest(request);
		body.setGetPerson(getPerson);
		envelope.setBody(body);

		return envelope;
	}

	private String marshalToXml(Envelope envelope) throws JAXBException {
		JAXBContext jaxbContext = JAXBContext.newInstance(Envelope.class);
		Marshaller marshaller = jaxbContext.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);

		// Use a StringWriter to capture the XML
		java.io.StringWriter sw = new java.io.StringWriter();
		marshaller.marshal(envelope, sw);
		return sw.toString();
	}

}
