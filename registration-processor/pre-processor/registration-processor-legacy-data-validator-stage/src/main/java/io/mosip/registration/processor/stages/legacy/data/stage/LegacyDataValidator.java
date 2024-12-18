package io.mosip.registration.processor.stages.legacy.data.stage;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONTokener;
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
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.exception.JsonProcessingException;
import io.mosip.registration.processor.core.code.ApiName;
import io.mosip.registration.processor.core.code.ModuleName;
import io.mosip.registration.processor.core.code.RegistrationTransactionStatusCode;
import io.mosip.registration.processor.core.code.RegistrationTransactionTypeCode;
import io.mosip.registration.processor.core.common.rest.dto.ErrorDTO;
import io.mosip.registration.processor.core.constant.LoggerFileConstant;
import io.mosip.registration.processor.core.constant.MappingJsonConstants;
import io.mosip.registration.processor.core.constant.ProviderStageName;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;
import io.mosip.registration.processor.core.exception.PacketManagerException;
import io.mosip.registration.processor.core.exception.ValidationFailedException;
import io.mosip.registration.processor.core.exception.util.PlatformSuccessMessages;
import io.mosip.registration.processor.core.http.RequestWrapper;
import io.mosip.registration.processor.core.http.ResponseWrapper;
import io.mosip.registration.processor.core.idrepo.dto.Documents;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.packet.dto.DocumentDto;
import io.mosip.registration.processor.core.packet.dto.PacketDto;
import io.mosip.registration.processor.core.packet.dto.PacketInfo;
import io.mosip.registration.processor.core.packet.dto.PacketInfoResponse;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.core.util.JsonUtil;
import io.mosip.registration.processor.core.util.RegistrationExceptionMapperUtil;
import io.mosip.registration.processor.packet.storage.dto.Document;
import io.mosip.registration.processor.packet.storage.dto.FieldResponseDto;
import io.mosip.registration.processor.packet.storage.utils.CredentialManagerUtil;
import io.mosip.registration.processor.packet.storage.utils.FingrePrintConvertor;
import io.mosip.registration.processor.packet.storage.utils.IdSchemaUtil;
import io.mosip.registration.processor.packet.storage.utils.PriorityBasedPacketManagerService;
import io.mosip.registration.processor.packet.storage.utils.Utilities;
import io.mosip.registration.processor.stages.legacy.data.dto.Body;
import io.mosip.registration.processor.stages.legacy.data.dto.Demographics;
import io.mosip.registration.processor.stages.legacy.data.dto.Envelope;
import io.mosip.registration.processor.stages.legacy.data.dto.Fingerprint;
import io.mosip.registration.processor.stages.legacy.data.dto.Header;
import io.mosip.registration.processor.stages.legacy.data.dto.Password;
import io.mosip.registration.processor.stages.legacy.data.dto.Position;
import io.mosip.registration.processor.stages.legacy.data.dto.Request;
import io.mosip.registration.processor.stages.legacy.data.dto.Response;
import io.mosip.registration.processor.stages.legacy.data.dto.TransactionStatus;
import io.mosip.registration.processor.stages.legacy.data.dto.UsernameToken;
import io.mosip.registration.processor.stages.legacy.data.dto.VerifyPerson;
import io.mosip.registration.processor.stages.legacy.data.dto.VerifyPersonResponse;
import io.mosip.registration.processor.stages.legacy.data.stage.exception.PacketOnHoldException;
import io.mosip.registration.processor.stages.legacy.data.util.LegacyDataApiUtility;
import io.mosip.registration.processor.status.code.RegistrationStatusCode;
import io.mosip.registration.processor.status.dto.InternalRegistrationStatusDto;
import io.mosip.registration.processor.status.dto.RegistrationStatusDto;
import io.mosip.registration.processor.status.dto.SyncRegistrationDto;
import io.mosip.registration.processor.status.dto.SyncResponseDto;
import io.mosip.registration.processor.status.entity.SyncRegistrationEntity;
import io.mosip.registration.processor.status.service.RegistrationStatusService;
import io.mosip.registration.processor.status.service.SyncRegistrationService;
import io.mosip.registration.processor.status.utilities.RegistrationUtility;

@Service
public class LegacyDataValidator {
	private static Logger regProcLogger = RegProcessorLogger.getLogger(LegacyDataValidator.class);

	public static final String INDIVIDUAL_TYPE_UIN = "UIN";

	private static final String ID = "mosip.commmons.packetmanager";
	private static final String VERSION = "v1";

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

	@Autowired
	private SyncRegistrationService<SyncResponseDto, SyncRegistrationDto> syncRegistrationService;

	@Autowired
	private IdSchemaUtil idSchemaUtil;

	@Autowired
	private ObjectMapper objectMapper;

	@Value("${mosip.regproc.legacydata.validator.tpi.username}")
	private String username;

	@Value("${mosip.regproc.legacydata.validator.tpi.password}")
	private String password;

	@Autowired
	private CredentialManagerUtil credentialManagerUtil;

	public boolean validate(String registrationId, InternalRegistrationStatusDto registrationStatusDto)
			throws ApisResourceAccessException, PacketManagerException, JsonProcessingException, IOException,
			ValidationFailedException, PacketOnHoldException, JAXBException, NoSuchAlgorithmException,
			NumberFormatException, JSONException {
		boolean isValidPacket = false;
		regProcLogger.debug("validate called for registrationId {}", registrationId);

		String NIN = packetManagerService.getFieldByMappingJsonKey(registrationId, MappingJsonConstants.NIN,
				registrationStatusDto.getRegistrationType(), ProviderStageName.LEGACY_DATA_VALIDATOR);

		JSONObject jSONObject = utility.getIdentityJSONObjectByHandle(NIN);
		if (jSONObject == null) {
			Map<String, String> positionAndWsqMap = getBiometricsWSQFormat(registrationId, registrationStatusDto);
			boolean isPresentInlegacySystem = false;
			// fetch legacy system data by calling api
			isPresentInlegacySystem = checkNINAVailableInLegacy(registrationId, NIN, positionAndWsqMap);
			if (isPresentInlegacySystem) {
					// Call for ondemand migration of packet by passing NIN
					// get Demographic details from legacy and biometrics and document from RENEWAL
					// and create packet using packet manager with NEW
					// TODO this to call api of migration to get demographic
					Response response = new Response();
					Demographics demographics = new Demographics();
					io.mosip.registration.processor.core.packet.dto.PacketInfo packetInfo = createOnDemandPacket(
							demographics, registrationStatusDto);
					if (packetInfo != null) {
						boolean storageFlag = createSyncAndRegistration(packetInfo,
								registrationStatusDto.getRegistrationStageName());
						isValidPacket = true;
						// update registrationStatusDto status as MERGED and comment registration id
					} else {
						// reprocess it if any
					}

			} else {
				throw new ValidationFailedException(StatusUtil.LEGACY_DATA_VALIDATION_FAILED.getMessage(),
						StatusUtil.LEGACY_DATA_VALIDATION_FAILED.getCode());
			}
		} else {
			isValidPacket = true;
		}

		regProcLogger.debug("validate call ended for registrationId {}", registrationId);
		return isValidPacket;
	}

	private boolean createSyncAndRegistration(PacketInfo packetInfo,String stageName) {
		boolean storageFlag = false;
		SyncRegistrationEntity syncRegistrationEntity = createSyncEntity(packetInfo);
		syncRegistrationEntity = syncRegistrationService.saveSyncRegistrationEntity(syncRegistrationEntity);
		storageFlag = createRegistrationStatusEntity(stageName, syncRegistrationEntity);
		return storageFlag;
	}

	private SyncRegistrationEntity createSyncEntity(PacketInfo packetInfo) {
		SyncRegistrationEntity syncRegistrationEntity = new SyncRegistrationEntity();
		syncRegistrationEntity.setRegistrationId(packetInfo.getId().trim());
		syncRegistrationEntity.setLangCode("eng");
		syncRegistrationEntity.setRegistrationType(packetInfo.getProcess());
		syncRegistrationEntity.setPacketHashValue("0");
		syncRegistrationEntity.setPacketSize(new BigInteger("0"));
		syncRegistrationEntity.setSupervisorStatus("APPROVED");
		syncRegistrationEntity.setPacketId(packetInfo.getId());
		syncRegistrationEntity.setReferenceId(packetInfo.getRefId());
		syncRegistrationEntity.setCreatedBy("MOSIP");
		syncRegistrationEntity.setCreateDateTime(LocalDateTime.now(ZoneId.of("UTC")));
		syncRegistrationEntity.setWorkflowInstanceId(RegistrationUtility.generateId());
		return syncRegistrationEntity;
	}

	private io.mosip.registration.processor.core.packet.dto.PacketInfo createOnDemandPacket(Demographics demographics,
			InternalRegistrationStatusDto registrationStatusDto) throws ApisResourceAccessException,
			PacketManagerException,
			JsonProcessingException, IOException, NumberFormatException, JSONException {
		String registrationId = registrationStatusDto.getRegistrationId();
		String registrationType = registrationStatusDto.getRegistrationType();
		String schemaVersion = packetManagerService.getFieldByMappingJsonKey(registrationStatusDto.getRegistrationId(),
				MappingJsonConstants.IDSCHEMA_VERSION, registrationType, ProviderStageName.LEGACY_DATA_VALIDATOR);

		Map<String, String> fieldMap = packetManagerService.getFields(registrationId,
				idSchemaUtil.getDefaultFields(Double.valueOf(schemaVersion)),registrationType, ProviderStageName.LEGACY_DATA_VALIDATOR);
		JSONObject demographicIdentity = new JSONObject();
		loadDemographicIdentity(fieldMap, demographicIdentity);
		Map<String, DocumentDto> documents=getAllDocumentsByRegId(registrationId, registrationType, demographicIdentity);
		Map<String, BiometricRecord> biometrics = getBiometrics(registrationId, registrationType, demographicIdentity);
		List<FieldResponseDto> audits = packetManagerService.getAudits(registrationId, registrationType,
				ProviderStageName.LEGACY_DATA_VALIDATOR);
		List<Map<String, String>> auditList = new ArrayList<>();
		for (FieldResponseDto dto : audits) {
			auditList.add(dto.getFields());
		}
		Map<String, String> metaInfo = packetManagerService.getMetaInfo(registrationId, registrationType,
				ProviderStageName.LEGACY_DATA_VALIDATOR);
		SyncRegistrationEntity regEntity = syncRegistrationService
				.findByWorkflowInstanceId(registrationStatusDto.getWorkflowInstanceId());
		PacketDto packetDto = new PacketDto();
		packetDto.setId(registrationId);
		packetDto.setSource("REGISTRATION_CLIENT");
		packetDto.setProcess("NEW");
		packetDto.setRefId(regEntity.getReferenceId());
		packetDto.setSchemaVersion(schemaVersion);
		packetDto.setSchemaJson(idSchemaUtil.getIdSchema(Double.parseDouble(schemaVersion)));
		// TODO need to uncomment
		// packetDto.setFields(demographics.getFields());
		packetDto.setFields(fieldMap);
		packetDto.setAudits(auditList);
		packetDto.setMetaInfo(metaInfo);
		packetDto.setDocuments(documents);
		packetDto.setBiometrics(biometrics);
		RequestWrapper<PacketDto> request = new RequestWrapper<>();
		request.setId(ID);
		request.setVersion(VERSION);
		request.setRequesttime(DateUtils.getUTCCurrentDateTime());
		request.setRequest(packetDto);
		ResponseWrapper responseWrapper = (ResponseWrapper<?>) restApi
				.putApi(ApiName.PACKETMANAGER_CREATE_PACKET, null, "", "", request, ResponseWrapper.class,
						null);
		if ((responseWrapper.getErrors() != null && !responseWrapper.getErrors().isEmpty())
				|| responseWrapper.getResponse() == null) {
			ErrorDTO error = (ErrorDTO) responseWrapper.getErrors().get(0);
		} else {
			PacketInfoResponse packetInfoResponse = mapper
					.readValue(mapper.writeValueAsString(responseWrapper.getResponse()),
					PacketInfoResponse.class);
			return packetInfoResponse.getPacketinfoList().get(0);
		}
		return null;
	}

	private Map<String, String> getBiometricsWSQFormat(String registrationId,
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
		System.out.println(request);
		String response = (String) restApi.postApi(ApiName.GETPERSONURL, "", "", request, String.class,
				MediaType.TEXT_XML);
		JAXBContext jaxbContext = JAXBContext.newInstance(Envelope.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		StringReader reader = new StringReader(response);
		Envelope responseEnvelope = (Envelope) unmarshaller.unmarshal(reader);
		VerifyPersonResponse verifyPersonResponse = responseEnvelope.getBody().getVerifyPersonResponse();
		TransactionStatus transactionStatus = verifyPersonResponse.getReturnElement().getTransactionStatus();
		if (transactionStatus.getTransactionStatus().equalsIgnoreCase("Ok")) {
			if (verifyPersonResponse.getReturnElement().isMatchingStatus()) {
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

	private Envelope createGetPersonRequest(String NIN, Map<String, String> positionAndWsqMap)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {

		byte[] nonceBytes = legacyDataApiUtility.generateNonce();
		String nonce = CryptoUtil.encodeToPlainBase64(nonceBytes);

		String timestamp = legacyDataApiUtility.createTimestamp();
		byte[] createdDigestBytes = timestamp.getBytes("UTF-8");

		byte[] passwordHashBytes = legacyDataApiUtility.hashPassword(password);
		String passwordDigest = legacyDataApiUtility.generateDigest(nonceBytes, createdDigestBytes, passwordHashBytes);

		// CredentialManagerUtil credentials =
		// credentialManagerUtil.withUsername(username).withPassword(password)
		// .build();

		// Proceed with using credentials
		// String nonce = credentials.getNonce();
		/// String created = credentials.getCreatedDatetime();
		// String passwordDigest = credentials.getPasswordDigest();
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

	private Map<String, DocumentDto> getAllDocumentsByRegId(String regId, String process,
			JSONObject demographicIdentity)
			throws IOException, ApisResourceAccessException, PacketManagerException, JsonProcessingException
	{
		JSONObject idJSON = demographicIdentity;
		List<Documents> applicantDocuments = new ArrayList<>();
		JSONObject docJson = utility.getRegistrationProcessorMappingJson(MappingJsonConstants.DOCUMENT);
		Map<String, DocumentDto> documents = new HashMap<String, DocumentDto>();
		for (Object doc : docJson.values()) {
			Map docMap = (LinkedHashMap) doc;
			String docValue = docMap.values().iterator().next().toString();
			HashMap<String, String> docInIdentityJson = (HashMap<String, String>) idJSON.get(docValue);
			if (docInIdentityJson != null) {
				DocumentDto documentDto = getIdDocument(regId, docValue, process);
				if (documentDto != null) {
					documents.put(docValue, documentDto);
				}
			}

		}

		return documents;
	}

	private DocumentDto getIdDocument(String registrationId, String dockey, String process)
			throws IOException, ApisResourceAccessException, PacketManagerException,
			io.mosip.kernel.core.util.exception.JsonProcessingException {

		Document document = packetManagerService.getDocument(registrationId, dockey, process,
				ProviderStageName.UIN_GENERATOR);
		if (document != null) {
			DocumentDto documentDto = new DocumentDto();
			documentDto.setDocument(document.getDocument());
			documentDto.setFormat(document.getFormat());
			documentDto.setType(document.getFormat());
			documentDto.setValue(document.getValue());
			return documentDto;
		}
		return null;
	}

	private void loadDemographicIdentity(Map<String, String> fieldMap, JSONObject demographicIdentity)
			throws IOException, JSONException {
		for (Map.Entry e : fieldMap.entrySet()) {
			if (e.getValue() != null) {
				String value = e.getValue().toString();
				if (value != null) {
					Object json = new JSONTokener(value).nextValue();
					if (json instanceof org.json.JSONObject) {
						HashMap<String, Object> hashMap = objectMapper.readValue(value, HashMap.class);
						demographicIdentity.putIfAbsent(e.getKey(), hashMap);
					} else if (json instanceof JSONArray) {
						List jsonList = new ArrayList<>();
						JSONArray jsonArray = new JSONArray(value);
						for (int i = 0; i < jsonArray.length(); i++) {
							Object obj = jsonArray.get(i);
							HashMap<String, Object> hashMap = objectMapper.readValue(obj.toString(), HashMap.class);
							jsonList.add(hashMap);
						}
						demographicIdentity.putIfAbsent(e.getKey(), jsonList);
					} else
						demographicIdentity.putIfAbsent(e.getKey(), value);
				} else
					demographicIdentity.putIfAbsent(e.getKey(), value);
			}
		}
	}

	private Map<String, BiometricRecord> getBiometrics(String registrationId, String registrationType,
			JSONObject demographicIdentity)
			throws IOException, ApisResourceAccessException, PacketManagerException, JsonProcessingException
	{
		Map<String, BiometricRecord> biometricData = new HashMap<String, BiometricRecord>();
		JSONObject idJSON = demographicIdentity;
		JSONObject identityJson = utility.getRegistrationProcessorMappingJson(MappingJsonConstants.IDENTITY);
		String applicantBiometricLabel = JsonUtil.getJSONValue(
				JsonUtil.getJSONObject(identityJson, MappingJsonConstants.INDIVIDUAL_BIOMETRICS),
				MappingJsonConstants.VALUE);

		HashMap<String, String> applicantBiometric = (HashMap<String, String>) idJSON.get(applicantBiometricLabel);
		if (applicantBiometric != null) {
			BiometricRecord biometricRecord = packetManagerService.getBiometrics(registrationId, applicantBiometricLabel, registrationType,
					ProviderStageName.LEGACY_DATA_VALIDATOR);
			if (biometricRecord != null) {
				biometricData.put(applicantBiometricLabel, biometricRecord);
			}
		}
		return biometricData;
		}

		private boolean createRegistrationStatusEntity(String stageName, SyncRegistrationEntity regEntity) {
			Boolean storageFlag = false;
			InternalRegistrationStatusDto dto = registrationStatusService.getRegistrationStatus(
					regEntity.getRegistrationId(), regEntity.getRegistrationType(), 1,
					regEntity.getWorkflowInstanceId());
			if (dto == null) {
				dto = new InternalRegistrationStatusDto();
				dto.setRetryCount(0);
			} else {
				int retryCount = dto.getRetryCount() != null ? dto.getRetryCount() + 1 : 1;
				dto.setRetryCount(retryCount);

			}
			dto.setRegistrationId(regEntity.getRegistrationId());
			dto.setLatestTransactionTypeCode(RegistrationTransactionTypeCode.LEGACY_DATA_VALIDATE.toString());
			dto.setLatestTransactionTimes(DateUtils.getUTCCurrentDateTime());
			dto.setRegistrationStageName(stageName);
			dto.setRegistrationType(regEntity.getRegistrationType());
			dto.setReferenceRegistrationId(null);
			dto.setStatusCode(RegistrationStatusCode.PROCESSING.toString());
			dto.setLangCode("eng");
			dto.setStatusComment(StatusUtil.ON_DEMAND_PACKET_CREATION_SUCCESS.getMessage());
			dto.setSubStatusCode(StatusUtil.ON_DEMAND_PACKET_CREATION_SUCCESS.getCode());
			dto.setReProcessRetryCount(0);
			dto.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.SUCCESS.toString());
			dto.setIsActive(true);
			dto.setCreatedBy("MOSIP");
			dto.setIsDeleted(false);
			dto.setSource(regEntity.getSource());
			dto.setIteration(1);
			dto.setWorkflowInstanceId(regEntity.getWorkflowInstanceId());

			/** Module-Id can be Both Success/Error code */
			String moduleId = PlatformSuccessMessages.RPR_LEGACY_DATA_VALIDATE.getCode();
			String moduleName = ModuleName.LEGACY_DATA.toString();
			registrationStatusService.addRegistrationStatus(dto, moduleId, moduleName);
			storageFlag = true;
			return storageFlag;
		}

}
