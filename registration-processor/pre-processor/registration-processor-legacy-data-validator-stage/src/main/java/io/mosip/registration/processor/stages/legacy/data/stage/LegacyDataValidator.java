package io.mosip.registration.processor.stages.legacy.data.stage;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.exception.JsonProcessingException;
import io.mosip.registration.processor.core.code.ApiName;
import io.mosip.registration.processor.core.constant.MappingJsonConstants;
import io.mosip.registration.processor.core.constant.ProviderStageName;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;
import io.mosip.registration.processor.core.exception.PacketManagerException;
import io.mosip.registration.processor.core.exception.ValidationFailedException;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.core.util.JsonUtil;
import io.mosip.registration.processor.core.util.RegistrationExceptionMapperUtil;
import io.mosip.registration.processor.packet.storage.utils.FingrePrintConvertor;
import io.mosip.registration.processor.packet.storage.utils.PriorityBasedPacketManagerService;
import io.mosip.registration.processor.packet.storage.utils.Utilities;
import io.mosip.registration.processor.stages.legacy.data.dto.Body;
import io.mosip.registration.processor.stages.legacy.data.dto.Envelope;
import io.mosip.registration.processor.stages.legacy.data.dto.Fingerprint;
import io.mosip.registration.processor.stages.legacy.data.dto.Header;
import io.mosip.registration.processor.stages.legacy.data.dto.Password;
import io.mosip.registration.processor.stages.legacy.data.dto.Position;
import io.mosip.registration.processor.stages.legacy.data.dto.Request;
import io.mosip.registration.processor.stages.legacy.data.dto.UsernameToken;
import io.mosip.registration.processor.stages.legacy.data.dto.VerifyPerson;
import io.mosip.registration.processor.stages.legacy.data.dto.VerifyPersonResponse;
import io.mosip.registration.processor.stages.legacy.data.stage.exception.PacketOnHoldException;
import io.mosip.registration.processor.stages.legacy.data.util.LegacyDataApiUtility;
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

		String NIN = packetManagerService.getFieldByMappingJsonKey(registrationId, MappingJsonConstants.NIN,
				registrationStatusDto.getRegistrationType(), ProviderStageName.LEGACY_DATA_VALIDATOR);

		JSONObject jSONObject = utility.getIdentityJSONObjectByHandle(NIN);
		if (jSONObject == null) {
			Map<String, String> positionAndWsqMap = getBiometrics(registrationId, registrationStatusDto);
			boolean isPresentInlegacySystem = false;
			// fetch legacy system data by calling api
			isPresentInlegacySystem = checkNINAVailableInLegacy(registrationId, NIN, positionAndWsqMap);
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

	private Map<String, String> getBiometrics(String registrationId,
			InternalRegistrationStatusDto registrationStatusDto)
			throws IOException, ApisResourceAccessException, PacketManagerException, JsonProcessingException,
			ValidationFailedException {
		
		JSONObject regProcessorIdentityJson = utility
				.getRegistrationProcessorMappingJson(MappingJsonConstants.IDENTITY);
		String individualBiometricsLabel = JsonUtil.getJSONValue(
				JsonUtil.getJSONObject(regProcessorIdentityJson, MappingJsonConstants.INDIVIDUAL_BIOMETRICS),
				MappingJsonConstants.VALUE);
		List<String> modalities = new ArrayList<>();
		modalities.add("Finger");
		BiometricRecord biometricRecord = packetManagerService.getBiometrics(registrationId,
				individualBiometricsLabel,
				modalities, registrationStatusDto.getRegistrationType(),
				ProviderStageName.LEGACY_DATA_VALIDATOR);
		if (biometricRecord == null || biometricRecord.getSegments() == null
				|| biometricRecord.getSegments().isEmpty()) {
			throw new ValidationFailedException(StatusUtil.LEGACY_DATA_VALIDATION_FAILED.getMessage(),
					StatusUtil.LEGACY_DATA_VALIDATION_FAILED.getCode());
		}
		Map<String, byte[]> isoImageMap = new HashMap<String, byte[]>();
		for (BIR bir : biometricRecord.getSegments()) {
         if(bir.getBdbInfo().getSubtype() != null) {
				String subType = String.join(" ", bir.getBdbInfo().getSubtype());
				String position = Position.getValueFromKey(subType);
				if(bir.getBdb()!=null) {
					isoImageMap.put(position, bir.getBdb());
				}
         }
		}
		Map<String, String> wsqFormatBiometrics = convertISOToWSQFormat(isoImageMap);

		return wsqFormatBiometrics;
	}

	private Map<String, String> convertISOToWSQFormat(Map<String, byte[]> isoImageMap) throws IOException {
		Map<String, String> wsqFormatBiometrics = new HashMap<String, String>();
		for (Map.Entry<String, byte[]> entry : isoImageMap.entrySet()) {
			byte[] wsqData = FingrePrintConvertor.convertIsoToWsq(entry.getValue());
			FingrePrintConvertor.getImage(wsqData);
			wsqFormatBiometrics.put(entry.getKey(), CryptoUtil.encodeToPlainBase64(wsqData));
		}
		System.out.println("map" + wsqFormatBiometrics);
		return wsqFormatBiometrics;
	}

	private boolean checkNINAVailableInLegacy(String registrationId, String NIN, Map<String, String> positionAndWsqMap)
			throws JAXBException, ApisResourceAccessException, NoSuchAlgorithmException, UnsupportedEncodingException {
		boolean isValid = false;
		Envelope requestEnvelope = createGetPersonRequest(NIN, positionAndWsqMap);
		String request = marshalToXml(requestEnvelope);
		String response = (String) restApi.postApi(ApiName.GETPERSONURL, "", "", request, String.class,
				MediaType.TEXT_XML);
		JAXBContext jaxbContext = JAXBContext.newInstance(Envelope.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		StringReader reader = new StringReader(response);
		Envelope responseEnvelope = (Envelope) unmarshaller.unmarshal(reader);
		VerifyPersonResponse verifyPersonResponse = responseEnvelope.getBody().getGetPersonResponse();
		/*TransactionStatus transactionStatus = verifyPersonResponse.getReturnData().getTransactionStatus();
		if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Ok")) {
			if (verifyPersonResponse.getReturnData().getNationalId().equals(NIN)) {
				isValid = true;
			}
		} else if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Error")) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					registrationId,
					RegistrationStatusCode.FAILED.toString() + transactionStatus.getError().getCode()
							+ transactionStatus.getError().getMessage());
		}*/
		return isValid;
	}

	private Envelope createGetPersonRequest(String NIN, Map<String, String> positionAndWsqMap)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {
		byte[] nonceBytes = legacyDataApiUtility.generateNonce();
		String nonce = CryptoUtil.encodeToPlainBase64(nonceBytes);

		String timestamp = legacyDataApiUtility.createTimestamp();
		byte[] createdDigestBytes = timestamp.getBytes("UTF-8");

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
		VerifyPerson verifyPerson = new VerifyPerson();
		Request request = new Request();
		request.setNationalId(NIN);
		List<Fingerprint> fingerprints = new ArrayList<Fingerprint>();
		for (Map.Entry<String, String> entry : positionAndWsqMap.entrySet()) {
			Fingerprint fingerprint = new Fingerprint();
			fingerprint.setPosition(entry.getKey());
			fingerprint.setWsq(entry.getValue());
			fingerprints.add(fingerprint);
		}
		request.setFingerprints(fingerprints);
		verifyPerson.setRequest(request);
		body.setVerifyPerson(verifyPerson);
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
