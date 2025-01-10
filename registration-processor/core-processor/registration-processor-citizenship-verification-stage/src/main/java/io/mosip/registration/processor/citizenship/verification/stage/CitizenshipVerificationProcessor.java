package io.mosip.registration.processor.citizenship.verification.stage;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.kernel.core.util.exception.JsonProcessingException;
import io.mosip.registration.processor.citizenship.verification.constants.CitizenshipType;
import io.mosip.registration.processor.citizenship.verification.constants.Relationship;
import io.mosip.registration.processor.citizenship.verification.service.NinUsageService;
import io.mosip.registration.processor.core.abstractverticle.MessageBusAddress;
import io.mosip.registration.processor.core.abstractverticle.MessageDTO;
import io.mosip.registration.processor.core.code.EventId;
import io.mosip.registration.processor.core.code.EventName;
import io.mosip.registration.processor.core.code.EventType;
import io.mosip.registration.processor.core.code.ModuleName;
import io.mosip.registration.processor.core.code.RegistrationExceptionTypeCode;
import io.mosip.registration.processor.core.code.RegistrationTransactionStatusCode;
import io.mosip.registration.processor.core.code.RegistrationTransactionTypeCode;

import io.mosip.registration.processor.core.constant.MappingJsonConstants;
import io.mosip.registration.processor.core.constant.ProviderStageName;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;
import io.mosip.registration.processor.core.exception.PacketManagerException;
import io.mosip.registration.processor.core.exception.util.PlatformErrorMessages;
import io.mosip.registration.processor.core.exception.util.PlatformSuccessMessages;
import io.mosip.registration.processor.core.logger.LogDescription;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.core.status.util.TrimExceptionMessage;
import io.mosip.registration.processor.core.util.RegistrationExceptionMapperUtil;
import io.mosip.registration.processor.packet.manager.decryptor.Decryptor;
import io.mosip.registration.processor.packet.storage.exception.IdRepoAppException;
import io.mosip.registration.processor.packet.storage.utils.Utilities;
import io.mosip.registration.processor.rest.client.audit.builder.AuditLogRequestBuilder;
import io.mosip.registration.processor.status.code.RegistrationStatusCode;
import io.mosip.registration.processor.status.dto.InternalRegistrationStatusDto;
import io.mosip.registration.processor.status.dto.RegistrationAdditionalInfoDTO;
import io.mosip.registration.processor.status.dto.RegistrationStatusDto;
import io.mosip.registration.processor.status.entity.SyncRegistrationEntity;
import io.mosip.registration.processor.status.service.RegistrationStatusService;

@Service
public class CitizenshipVerificationProcessor {

	private static final String USER = "MOSIP_SYSTEM";

	private TrimExceptionMessage trimExpMessage = new TrimExceptionMessage();

	private static Logger regProcLogger = RegProcessorLogger.getLogger(CitizenshipVerificationProcessor.class);

	@Autowired
	private AuditLogRequestBuilder auditLogRequestBuilder;

	@Autowired
	private NinUsageService ninUsageService;

	@Autowired
	RegistrationStatusService<String, InternalRegistrationStatusDto, RegistrationStatusDto> registrationStatusService;

	@Autowired
	private Utilities utility;

	@Autowired
	RegistrationExceptionMapperUtil registrationStatusMapperUtil;

	private ObjectMapper objectMapper;

	@Value("${mosip.registration.processor.datetime.pattern}")
	private String dateformat;

	public MessageDTO process(MessageDTO object) {

		LogDescription description = new LogDescription();
		boolean isTransactionSuccessful = false;
		String registrationId = object.getRid();

		object.setMessageBusAddress(MessageBusAddress.CITIZENSHIP_VERIFICATION_BUS_IN);
		object.setIsValid(Boolean.FALSE);
		object.setInternalError(Boolean.FALSE);

		regProcLogger.debug("Process called for registrationId {}", registrationId);

		InternalRegistrationStatusDto registrationStatusDto = registrationStatusService.getRegistrationStatus(
				registrationId, object.getReg_type(), object.getIteration(), object.getWorkflowInstanceId());

		registrationStatusDto
				.setLatestTransactionTypeCode(RegistrationTransactionTypeCode.CITIZENSHIP_VERIFICATION.toString());
		registrationStatusDto.setRegistrationStageName(ProviderStageName.CITIZENSHIP_VERIFICATION.toString());

		try {
			if (validatePacketCitizenship(registrationId, object, registrationStatusDto, description)) {
				object.setIsValid(Boolean.TRUE);
				object.setInternalError(Boolean.FALSE);
				regProcLogger.info("Citizenship Verification passed for registrationId: {}", registrationId);
				registrationStatusDto
						.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.SUCCESS.toString());
				registrationStatusDto.setStatusComment(StatusUtil.CITIZENSHIP_VERIFICATION_SUCCESS.getMessage());
				registrationStatusDto.setSubStatusCode(StatusUtil.CITIZENSHIP_VERIFICATION_SUCCESS.getCode());
				registrationStatusDto.setStatusCode(RegistrationStatusCode.PROCESSING.toString());

				description.setMessage(PlatformSuccessMessages.RPR_CITIZENSHIP_VERIFICATION_SUCCESS.getMessage()
						+ " -- " + registrationId);
				description.setCode(PlatformSuccessMessages.RPR_CITIZENSHIP_VERIFICATION_SUCCESS.getCode());
				isTransactionSuccessful = true;
			} else {

				object.setIsValid(Boolean.FALSE);
				object.setInternalError(Boolean.FALSE);
				regProcLogger.info(
						"Citizenship Verification failed for registrationId: {}. Packet goes to manual verification stage.",
						registrationId);
			}

		} catch (Exception e) {
			updateDTOsAndLogError(registrationStatusDto, RegistrationStatusCode.FAILED,
					StatusUtil.UNKNOWN_EXCEPTION_OCCURED, RegistrationExceptionTypeCode.EXCEPTION, description,
					PlatformErrorMessages.RPR_CITIZENSHIP_VERIFICATION_FAILED, e);
			object.setIsValid(Boolean.FALSE);
			object.setInternalError(Boolean.TRUE);
			regProcLogger.error("In Registration Processor", "Citizenship Verification",
					"Failed to validate citizenship for packet: " + e.getMessage());
		} finally {
			if (object.getInternalError()) {
				int retryCount = registrationStatusDto.getRetryCount() != null
						? registrationStatusDto.getRetryCount() + 1
						: 1;
				registrationStatusDto.setRetryCount(retryCount);
				updateErrorFlags(registrationStatusDto, object);
			}
			registrationStatusDto.setUpdatedBy(USER);
			String moduleId = description.getCode();
			String moduleName = ModuleName.CITIZENSHIP_VERIFICATION.toString();
			registrationStatusService.updateRegistrationStatus(registrationStatusDto, moduleId, moduleName);
			updateAudit(description, isTransactionSuccessful, moduleId, moduleName, registrationId);
		}

		return object;

	}

	private void updateAudit(LogDescription description, boolean isTransactionSuccessful, String moduleId,
			String moduleName, String registrationId) {
		String eventId = isTransactionSuccessful ? EventId.RPR_402.toString() : EventId.RPR_405.toString();
		String eventName = isTransactionSuccessful ? EventName.UPDATE.toString() : EventName.EXCEPTION.toString();
		String eventType = isTransactionSuccessful ? EventType.BUSINESS.toString() : EventType.SYSTEM.toString();

		auditLogRequestBuilder.createAuditRequestBuilder(description.getMessage(), eventId, eventName, eventType,
				moduleId, moduleName, registrationId);
	}

	private void updateErrorFlags(InternalRegistrationStatusDto registrationStatusDto, MessageDTO object) {
		object.setInternalError(true);
		if (registrationStatusDto.getLatestTransactionStatusCode()
				.equalsIgnoreCase(RegistrationTransactionStatusCode.REPROCESS.toString())) {
			object.setIsValid(true);
		} else {
			object.setIsValid(false);
		}
	}

	private void updateDTOsAndLogError(InternalRegistrationStatusDto registrationStatusDto,
			RegistrationStatusCode registrationStatusCode, StatusUtil statusUtil,
			RegistrationExceptionTypeCode registrationExceptionTypeCode, LogDescription description,
			PlatformErrorMessages platformErrorMessages, Exception e) {
		registrationStatusDto.setStatusCode(registrationStatusCode.toString());
		registrationStatusDto
				.setStatusComment(trimExpMessage.trimExceptionMessage(statusUtil.getMessage() + e.getMessage()));
		registrationStatusDto.setSubStatusCode(statusUtil.getCode());
		registrationStatusDto.setLatestTransactionStatusCode(
				registrationStatusMapperUtil.getStatusCode(registrationExceptionTypeCode));
		description.setMessage(platformErrorMessages.getMessage());
		description.setCode(platformErrorMessages.getCode());
		regProcLogger.error("Error in process for registration id {} {} {} {} {}",
				registrationStatusDto.getRegistrationId(), description.getCode(), platformErrorMessages.getMessage(),
				e.getMessage(), ExceptionUtils.getStackTrace(e));
	}

	private void logAndSetStatusError(InternalRegistrationStatusDto registrationStatusDto, String errorMessage,
			String subStatusCode, String statusComment, String statusCode, LogDescription description,
			String registrationId) {
		regProcLogger.error(errorMessage);
		registrationStatusDto.setLatestTransactionStatusCode(RegistrationTransactionStatusCode.FAILED.toString());
		registrationStatusDto.setStatusComment(statusComment);
		registrationStatusDto.setSubStatusCode(subStatusCode);
		registrationStatusDto.setStatusCode(statusCode);

		description.setMessage(statusComment + " -- " + registrationId);
		description.setCode(subStatusCode);

		regProcLogger.info("Updated registrationStatusDto: {}", registrationStatusDto);
	}

	private boolean validatePacketCitizenship(String registrationId, MessageDTO object,
			InternalRegistrationStatusDto registrationStatusDto, LogDescription description) {
		boolean ifCitizenshipValid = false;

		objectMapper = new ObjectMapper();

		try {
			regProcLogger.info("Starting citizenship validation for registration ID: {}", registrationId);
			// Consolidate fields into a single list,
			List<String> fieldsToFetch = new ArrayList<>(List.of(MappingJsonConstants.APPLICANT_TRIBE,
					MappingJsonConstants.APPLICANT_CITIZENSHIPTYPE, MappingJsonConstants.APPLICANT_DATEOFBIRTH,
					MappingJsonConstants.APPLICANT_CLAN,
					MappingJsonConstants.FATHER_NIN, MappingJsonConstants.FATHER_TRIBE,
					MappingJsonConstants.FATHER_CLAN,MappingJsonConstants.MOTHER_NIN,
					MappingJsonConstants.MOTHER_TRIBE, MappingJsonConstants.MOTHER_CLAN,
					MappingJsonConstants.GUARDIAN_NIN,MappingJsonConstants.GUARDIAN_RELATION_TO_APPLICANT,
					MappingJsonConstants.GUARDIAN_TRIBE_FORM, MappingJsonConstants.GUARDIAN_CLAN_FORM

			));

			// Fetch all fields in a single call
			Map<String, String> applicantFields = utility.getPacketManagerService().getFields(registrationId,
					fieldsToFetch, object.getReg_type(), ProviderStageName.CITIZENSHIP_VERIFICATION);


			regProcLogger.info("fields fetched {}: " + applicantFields.toString());
			System.out.println("fields fetched {}: " + applicantFields.toString());
			String citizenshipType = null;
			String jsonCitizenshipTypes = applicantFields.get(MappingJsonConstants.APPLICANT_CITIZENSHIPTYPE);

			try {

				List<Map<String, String>> citizenshipTypes = objectMapper.readValue(jsonCitizenshipTypes,
						new TypeReference<List<Map<String, String>>>() {
						});
				citizenshipType = citizenshipTypes.get(0).get("value");

			} catch (Exception e) {

			}
			System.out.println("****************************************************citizenshipType" + citizenshipType);
			if (!CitizenshipType.BIRTH.getCitizenshipType().equalsIgnoreCase(citizenshipType)) {
				regProcLogger.info("Citizenship verification failed: Not Citizen By Birth");
				logAndSetStatusError(registrationStatusDto,
						"Citizenship verification failed: Not Citizen By Birth for registrationId: " + registrationId,
						StatusUtil.CITIZENSHIP_VERIFICATION_NOT_CITIZEN_BYBIRTH.getCode(),
						StatusUtil.CITIZENSHIP_VERIFICATION_NOT_CITIZEN_BYBIRTH.getMessage(),
						RegistrationStatusCode.PROCESSING.toString(), description, registrationId);

				ifCitizenshipValid = false;

			} else {
				regProcLogger.info("Citizenship verification proceed: Citizen By Birth");

				applicantFields.put(MappingJsonConstants.AGE, String.valueOf(utility.getApplicantAge(registrationId,
						object.getReg_type(), ProviderStageName.CITIZENSHIP_VERIFICATION)));

				if (!checkIfAtLeastOneParentHasNIN(applicantFields)) {
					regProcLogger.info("Citizenship verification proceed: No parent has NIN");
					logAndSetStatusError(registrationStatusDto,
							"Citizenship verification proceed: No parent has NIN for registrationId: " + registrationId,
							StatusUtil.CITIZENSHIP_VERIFICATION_NO_PARENT_NIN.getCode(),
							StatusUtil.CITIZENSHIP_VERIFICATION_NO_PARENT_NIN.getMessage(),
							RegistrationStatusCode.PROCESSING.toString(), description, registrationId);
					ifCitizenshipValid = handleValidationWithNoParentNinFound(applicantFields, registrationStatusDto,
							description);
				} else {
					regProcLogger.info("Citizenship verification proceed: Atleast one parent has NIN");
					ifCitizenshipValid = handleValidationWithParentNinFound(applicantFields, registrationStatusDto,
							description);
				}
			}
		} catch (ApisResourceAccessException | PacketManagerException | JsonProcessingException | IOException e) {
			updateDTOsAndLogError(registrationStatusDto, RegistrationStatusCode.FAILED,
					StatusUtil.UNKNOWN_EXCEPTION_OCCURED, RegistrationExceptionTypeCode.EXCEPTION, description,
					PlatformErrorMessages.PACKET_MANAGER_EXCEPTION, e);

			object.setIsValid(Boolean.FALSE);
			object.setInternalError(Boolean.TRUE);
			regProcLogger.error("In Registration Processor", "Citizenship Verification",
					"Failed to validate citizenship for packet: "
							+ PlatformErrorMessages.PACKET_MANAGER_EXCEPTION.getMessage());
		}

		return ifCitizenshipValid;
	}

	private boolean checkIfAtLeastOneParentHasNIN(Map<String, String> fields) {
		String fatherNIN = fields.get("fatherNIN");
		String motherNIN = fields.get("motherNIN");
		return fatherNIN != null && !fatherNIN.isEmpty() || (motherNIN != null && !motherNIN.isEmpty());
	}

	private boolean handleValidationWithParentNinFound(Map<String, String> applicantFields,
	        InternalRegistrationStatusDto registrationStatusDto, LogDescription description) {

	    regProcLogger.info("Citizenship verification proceed: Handling validation with parents NIN found");
	    boolean isParentInfoValid = false;
	    DateTimeFormatter formatter = DateTimeFormatter.ofPattern(MappingJsonConstants.DATE_FORMAT);

	    String fatherNIN = applicantFields.get(MappingJsonConstants.FATHER_NIN);
	    regProcLogger.info("Father's NIN: " + fatherNIN);

	    String motherNIN = applicantFields.get(MappingJsonConstants.MOTHER_NIN);
	    regProcLogger.info("Mother's NIN: " + motherNIN);

	    LocalDate applicantDob = parseDate(applicantFields.get(MappingJsonConstants.APPLICANT_DATEOFBIRTH), formatter);
	    regProcLogger.info("Parsed applicant date of birth from string '" + applicantDob + "' to LocalDate: " + applicantDob);

	    if (applicantDob == null) {
	        regProcLogger.error("Invalid applicant date of birth.");
	        return false;
	    }

	    if (fatherNIN != null) {
	        isParentInfoValid = validateParentInfo(fatherNIN, "FATHER", applicantFields, applicantDob, formatter,
	                registrationStatusDto, description);
	    }

	    if (isParentInfoValid == false && motherNIN != null) {
	        isParentInfoValid = validateParentInfo(motherNIN, "MOTHER", applicantFields, applicantDob, formatter,
	                registrationStatusDto, description);
	    }

	    regProcLogger.error("Neither parent's NIN is provided.");
	    return isParentInfoValid;
	}


	private boolean validateParentInfo(String parentNin, String parentType, Map<String, String> applicantFields,
			LocalDate applicantDob, DateTimeFormatter formatter, InternalRegistrationStatusDto registrationStatusDto,
			LogDescription description) {

		regProcLogger.info("Citizenship verification proceed: Validating parent");
		if (parentNin == null) {
			return false;
		}

		try {
			if (ninUsageService.isNinUsedMorethanNtimes(parentNin, parentType)) {
				logAndSetStatusError(registrationStatusDto, parentType + "'s NIN is used more than N times.",
						StatusUtil.CITIZENSHIP_VERIFICATION_NIN_USAGE_EXCEEDED.getCode(),
						StatusUtil.CITIZENSHIP_VERIFICATION_NIN_USAGE_EXCEEDED.getMessage(),
						RegistrationStatusCode.PROCESSING.toString(), description,
						applicantFields.get("registrationId"));
				return false;
			}
			
			JSONObject parentInfoJson = utility.getIdentityJSONObjectByHandle(parentNin);

			if (parentInfoJson == null) {
				logAndSetStatusError(registrationStatusDto, parentType + "'s NIN not found in repo data.",
						StatusUtil.CITIZENSHIP_VERIFICATION_UIN_NOT_FOUND.getCode(),
						StatusUtil.CITIZENSHIP_VERIFICATION_UIN_NOT_FOUND.getMessage(),
						RegistrationStatusCode.PROCESSING.toString(), description,
						applicantFields.get("registrationId"));
				return false;

			}


			String parentDobStr = (String) parentInfoJson.get(MappingJsonConstants.APPLICANT_DATEOFBIRTH);
			LocalDate parentOrGuardianDob = parseDate(parentDobStr, formatter);
			regProcLogger.info("Parsed parent date of birth from string '" + parentDobStr + "' to LocalDate: "
					+ parentOrGuardianDob);

			if (parentOrGuardianDob == null
					|| !checkApplicantAgeWithParentOrGuardian(applicantDob, parentOrGuardianDob, 15)) {
				logAndSetStatusError(registrationStatusDto,
						parentType + "'s age difference with the applicant is less than 15 years.",
						StatusUtil.CITIZENSHIP_VERIFICATION_AGE_DIFFERENCE_FAILED.getCode(),
						StatusUtil.CITIZENSHIP_VERIFICATION_AGE_DIFFERENCE_FAILED.getMessage(),
						RegistrationStatusCode.PROCESSING.toString(), description,
						applicantFields.get("registrationId"));
				return false;

			}

			Map<String, String> person1Map = extractDemographics(parentType, parentInfoJson);
			regProcLogger.info("Extracted demographics for {}: {}", parentType, person1Map);

			Map<String, String> person2Map = extractApplicantDemographics(applicantFields);
			regProcLogger.info("Applicant Extracted demographics for {}: {}", parentType, person2Map);

			return ValidateTribeAndClan(person1Map, person2Map, registrationStatusDto, description, applicantFields);
		} catch (Exception e) {
			logAndSetStatusError(registrationStatusDto,
					"Error processing " + parentType + "'s information: " + e.getMessage(),
					StatusUtil.CITIZENSHIP_VERIFICATION_PARENT_INFO_PROCESSING_ERROR.getCode(),
					StatusUtil.CITIZENSHIP_VERIFICATION_PARENT_INFO_PROCESSING_ERROR.getMessage(),
					RegistrationStatusCode.FAILED.toString(), description, applicantFields.get("registrationId"));
			return false;
		}
	}

	private LocalDate parseDate(String dateStr, DateTimeFormatter formatter) {
		try {
			return LocalDate.parse(dateStr, formatter);
		} catch (DateTimeParseException e) {
			return null;
		}
	}

	private Map<String, String> extractDemographics(String parentType, JSONObject parentInfoJson) {
		Map<String, String> person1Map = new HashMap<>();
		person1Map.put(MappingJsonConstants.PERSON, parentType + " in NIRA System");
		ObjectMapper objectMapper = new ObjectMapper();

		extractAndPutValue(person1Map, MappingJsonConstants.TRIBE, parentInfoJson, MappingJsonConstants.PARENT_TRIBE,
				objectMapper);
		extractAndPutValue(person1Map, MappingJsonConstants.CLAN, parentInfoJson, MappingJsonConstants.PARENT_CLAN,
				objectMapper);

		return person1Map;
	}

	private void extractAndPutValue(Map<String, String> map, String key, JSONObject jsonObject, String jsonKey,
			ObjectMapper objectMapper) {
		String jsonString = null;
		try {
			jsonString = jsonObject.get(jsonKey).toString();
		} catch (Exception e) {

		}
		if (jsonString != null && !jsonString.isEmpty()) {
			try {
				List<Map<String, String>> list = objectMapper.readValue(jsonString,
						new TypeReference<List<Map<String, String>>>() {
						});
				if (!list.isEmpty()) {
					map.put(key, list.get(0).get("value"));
				}
			} catch (Exception e) {

			}
		}
	}

	private Map<String, String> extractApplicantDemographics(Map<String, String> applicantFields) {
		Map<String, String> person2Map = new HashMap<>();
		person2Map.put(MappingJsonConstants.PERSON, "Applicant");
		ObjectMapper objectMapper = new ObjectMapper();

		extractAndPutValue(person2Map, MappingJsonConstants.TRIBE,
				applicantFields.get(MappingJsonConstants.APPLICANT_TRIBE), objectMapper);
		extractAndPutValue(person2Map, MappingJsonConstants.CLAN,
				applicantFields.get(MappingJsonConstants.APPLICANT_CLAN), objectMapper);

		return person2Map;
	}

	private void extractAndPutValue(Map<String, String> map, String key, String jsonString, ObjectMapper objectMapper) {
		if (jsonString != null && !jsonString.isEmpty()) {
			try {
				List<Map<String, String>> list = objectMapper.readValue(jsonString,
						new TypeReference<List<Map<String, String>>>() {
						});
				if (!list.isEmpty()) {
					map.put(key, list.get(0).get("value"));
				}
			} catch (Exception e) {

			}
		}
	}

	private boolean ValidateTribeAndClan(Map<String, String> person1, Map<String, String> person2,
			InternalRegistrationStatusDto registrationStatusDto, LogDescription description,
			Map<String, String> applicantFields) {
		Boolean isValid = false;

		if (person1.get(MappingJsonConstants.TRIBE).equalsIgnoreCase(person2.get(MappingJsonConstants.TRIBE))) {

			if (person1.get(MappingJsonConstants.CLAN).equalsIgnoreCase(person2.get(MappingJsonConstants.CLAN))) {
				isValid = true;
			} else {

				logAndSetStatusError(registrationStatusDto,
						"Mismatch in " + person1.get(MappingJsonConstants.PERSON) + ", "
								+ person2.get(MappingJsonConstants.PERSON) + "'s " + MappingJsonConstants.CLAN
								+ " information.",
					StatusUtil.CITIZENSHIP_VERIFICATION_CLAN_MISMATCH.getCode(),
					StatusUtil.CITIZENSHIP_VERIFICATION_CLAN_MISMATCH.getMessage(),
					RegistrationStatusCode.PROCESSING.toString(), description,
					applicantFields.get("registrationId"));
			}
		} else {
			logAndSetStatusError(registrationStatusDto, "Mismatch in " + person1.get(MappingJsonConstants.PERSON) + ", "
					+ person2.get(MappingJsonConstants.PERSON) + "'s " + MappingJsonConstants.TRIBE + " information.",
				StatusUtil.CITIZENSHIP_VERIFICATION_TRIBE_MISMATCH.getCode(),
				StatusUtil.CITIZENSHIP_VERIFICATION_TRIBE_MISMATCH.getMessage(),
				RegistrationStatusCode.PROCESSING.toString(), description, applicantFields.get("registrationId"));
		}

		return isValid;
	}

	
	
	private boolean handleValidationWithNoParentNinFound(Map<String, String> applicantFields,
			InternalRegistrationStatusDto registrationStatusDto, LogDescription description) {

		String guardianNin = applicantFields.get(MappingJsonConstants.GUARDIAN_NIN);
		if (guardianNin == null) {

			logAndSetStatusError(registrationStatusDto, "GUARDIAN_NIN is missing. Stopping further processing.",
					StatusUtil.CITIZENSHIP_VERIFICATION_GUARDIAN_NIN_MISSING.getCode(),
					StatusUtil.CITIZENSHIP_VERIFICATION_GUARDIAN_NIN_MISSING.getMessage(),
					RegistrationStatusCode.PROCESSING.toString(), description, applicantFields.get("registrationId"));
			return false;
		} else {
			regProcLogger.info("GUARDIAN_NIN: " + guardianNin);
		}

		String guardianRelationToApplicantJson = applicantFields
				.get(MappingJsonConstants.GUARDIAN_RELATION_TO_APPLICANT);
		regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationToApplicantJson);

		ObjectMapper objectMapper = new ObjectMapper();
		String guardianRelationValue = null;
		try {
			List<Map<String, String>> guardianRelations = objectMapper.readValue(guardianRelationToApplicantJson,
					new TypeReference<List<Map<String, String>>>() {
					});
			guardianRelationValue = guardianRelations.get(0).get("value");
			regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationValue);
		} catch (Exception e) {
			regProcLogger.error("Error parsing GUARDIAN_RELATION_TO_APPLICANT JSON", e);
			return false;
		}

		boolean isValidGuardian = false;

		try {
			if (ninUsageService.isNinUsedMorethanNtimes(guardianNin, guardianRelationValue)) {

				logAndSetStatusError(registrationStatusDto,
						"NIN usage is over the limit for guardian NIN: " + guardianNin + ", relation: "
								+ guardianRelationValue,
						StatusUtil.CITIZENSHIP_VERIFICATION_NIN_USAGE_EXCEEDED.getCode(),
						StatusUtil.CITIZENSHIP_VERIFICATION_NIN_USAGE_EXCEEDED.getMessage(),
						RegistrationStatusCode.PROCESSING.toString(), description,
						applicantFields.get("registrationId"));
				return false;
			}
			
			if (guardianRelationValue.equalsIgnoreCase(Relationship.FIRST_COUSIN.getRelationship())) {
	            return true; // validate NIN usage for FIRST_COUSIN
	        }

			JSONObject guardianInfoJson = utility.getIdentityJSONObjectByHandle(guardianNin);
			regProcLogger.info("guardianInfoJson: " + guardianInfoJson);

			String status = utility.retrieveIdrepoJsonStatusForNIN(guardianNin);
			regProcLogger.info("status: " + status);

			if (guardianRelationValue.equalsIgnoreCase(Relationship.GRAND_FATHER_ON_FATHERS_SIDE.getRelationship())
					|| Relationship.GRAND_FATHER_ON_MOTHERS_SIDE.getRelationship()
							.equalsIgnoreCase(guardianRelationValue)) {
				isValidGuardian = validateGrandfatherRelationship(applicantFields, guardianInfoJson,
						registrationStatusDto, description);
				
			  } else if (guardianRelationValue.equalsIgnoreCase(Relationship.GRAND_MOTHER_ON_FATHERS_SIDE.getRelationship())
		                || guardianRelationValue.equalsIgnoreCase(Relationship.GRAND_MOTHER_ON_MOTHERS_SIDE.getRelationship())) {
		            isValidGuardian = validateGrandmotherRelationship(applicantFields, guardianInfoJson,
		                    registrationStatusDto, description);

			} else if (guardianRelationValue.equalsIgnoreCase(Relationship.BROTHER_OR_SISTER.getRelationship())) {
				isValidGuardian = validateSiblingRelationship(applicantFields, guardianInfoJson, registrationStatusDto,
						description);

			} else if (guardianRelationValue.equalsIgnoreCase(Relationship.MATERNAL_UNCLE_OR_AUNT.getRelationship())
					|| Relationship.PATERNAL_UNCLE_OR_AUNT.getRelationship().equalsIgnoreCase(guardianRelationValue)) {
				isValidGuardian = validateUncleAuntRelationship(applicantFields, guardianInfoJson,
						registrationStatusDto, description);
			}

			if (!isValidGuardian) {

				logAndSetStatusError(registrationStatusDto,
						"Guardian information validation failed for registrationId: "
								+ applicantFields.get("registrationId"),
						StatusUtil.CITIZENSHIP_VERIFICATION_GUARDIAN_VALIDATION_FAILED.getCode(),
						StatusUtil.CITIZENSHIP_VERIFICATION_GUARDIAN_VALIDATION_FAILED.getMessage(),
						RegistrationStatusCode.PROCESSING.toString(), description,
						applicantFields.get("registrationId"));
			}
			return isValidGuardian;
		} catch (Exception e) {

			logAndSetStatusError(registrationStatusDto,
					"Error during guardian information validation: " + e.getMessage(),
					StatusUtil.CITIZENSHIP_VERIFICATION_GUARDIAN_INFO_PROCESSING_ERROR.getCode(),
					StatusUtil.CITIZENSHIP_VERIFICATION_GUARDIAN_INFO_PROCESSING_ERROR.getMessage(),
					RegistrationStatusCode.FAILED.toString(), description, applicantFields.get("registrationId"));
			return false;
		}
	}
	

	private boolean checkApplicantAgeWithParentOrGuardian(LocalDate applicantDob, LocalDate parentOrGuardianDob,
			int ageCondition) {
		Period ageDifference = Period.between(parentOrGuardianDob, applicantDob);
		regProcLogger.info("Age difference is: {} years, {} months, and {} days.", ageDifference.getYears(),
				ageDifference.getMonths(), ageDifference.getDays());
		return ageDifference.getYears() >= ageCondition;
	}


	private boolean validateGrandmotherRelationship(Map<String, String> applicantFields, JSONObject guardianInfoJson,
	        InternalRegistrationStatusDto registrationStatusDto, LogDescription description)
	        throws IdRepoAppException, ApisResourceAccessException {

	    // Retrieve the guardian's NIN and validate its presence
	    String guardianNin = applicantFields.get(MappingJsonConstants.GUARDIAN_NIN);
	    if (guardianNin == null) {
	        regProcLogger.warn("GUARDIAN_NIN is missing. Stopping further processing.");
	        return false;
	    } else {
	        regProcLogger.info("GUARDIAN_NIN: " + guardianNin);
	    }

	    // Retrieve and parse the relationship to the applicant
	    String guardianRelationToApplicantJson = applicantFields.get(MappingJsonConstants.GUARDIAN_RELATION_TO_APPLICANT);
	    regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationToApplicantJson);

	    ObjectMapper objectMapper = new ObjectMapper();
	    String guardianRelationValue = null;
	    try {
	        List<Map<String, String>> guardianRelations = objectMapper.readValue(guardianRelationToApplicantJson,
	                new TypeReference<List<Map<String, String>>>() {});
	        guardianRelationValue = guardianRelations.get(0).get("value");
	        regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationValue);
	    } catch (Exception e) {
	        regProcLogger.error("Error parsing GUARDIAN_RELATION_TO_APPLICANT JSON", e);
	        return false;
	    }

	    // Retrieve and parse dates of birth for the guardian and applicant
	    String guardianDobStr = (String) guardianInfoJson.get(MappingJsonConstants.APPLICANT_DATEOFBIRTH);
	    DateTimeFormatter formatter = DateTimeFormatter.ofPattern(MappingJsonConstants.DATE_FORMAT);

	    LocalDate guardianDob = null;
	    LocalDate applicantDob = null;
	    try {
	        guardianDob = LocalDate.parse(guardianDobStr, formatter);
	        applicantDob = LocalDate.parse(applicantFields.get(MappingJsonConstants.APPLICANT_DATEOFBIRTH), formatter);
	    } catch (Exception e) {
	        regProcLogger.error("Error parsing dates of birth for guardian or applicant.", e);
	        return false;
	    }

	    regProcLogger.info("Applicant DOB: " + applicantDob);
	    regProcLogger.info("Guardian (grandmother) DOB: " + guardianDob);

	    // Validate age difference
	    if (!checkApplicantAgeWithParentOrGuardian(applicantDob, guardianDob, 20)) {
	        logAndSetStatusError(registrationStatusDto,
	                "Guardian (grandmother) is not at least 20 years older than the applicant for registrationId: "
	                        + applicantFields.get("registrationId"),
	                StatusUtil.CITIZENSHIP_VERIFICATION_AGE_DIFFERENCE_FAILED.getCode(),
	                StatusUtil.CITIZENSHIP_VERIFICATION_AGE_DIFFERENCE_FAILED.getMessage(),
	                RegistrationStatusCode.PROCESSING.toString(), description, applicantFields.get("registrationId"));
	        return false;
	    }

	    return true;
	}


	private boolean validateGrandfatherRelationship(Map<String, String> applicantFields, JSONObject guardianInfoJson,
			InternalRegistrationStatusDto registrationStatusDto, LogDescription description)
			throws IdRepoAppException, ApisResourceAccessException {

		String guardianNin = applicantFields.get(MappingJsonConstants.GUARDIAN_NIN);
		if (guardianNin == null) {
			regProcLogger.warn("GUARDIAN_NIN is missing. Stopping further processing.");
			return false;
		} else {
			regProcLogger.info("GUARDIAN_NIN: " + guardianNin);
		}


		String guardianRelationToApplicantJson = applicantFields
				.get(MappingJsonConstants.GUARDIAN_RELATION_TO_APPLICANT);
		regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationToApplicantJson);

		ObjectMapper objectMapper = new ObjectMapper();

		String guardianRelationValue = null;
		try {
			List<Map<String, String>> guardianRelations = objectMapper.readValue(guardianRelationToApplicantJson,
					new TypeReference<List<Map<String, String>>>() {
					});
			guardianRelationValue = guardianRelations.get(0).get("value");
			regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationValue);
		} catch (Exception e) {
			regProcLogger.error("Error parsing GUARDIAN_RELATION_TO_APPLICANT JSON", e);
			return false;
		}

		boolean isValidGuardian = true;

		String guardianDobStr = (String) guardianInfoJson.get(MappingJsonConstants.APPLICANT_DATEOFBIRTH);
																										
																											
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern(MappingJsonConstants.DATE_FORMAT);
		LocalDate parentOrGuardianDob = LocalDate.parse(guardianDobStr, formatter);
		LocalDate applicantDob = LocalDate.parse(applicantFields.get(MappingJsonConstants.APPLICANT_DATEOFBIRTH),
				formatter);

		regProcLogger.info("Applicant DOB: " + applicantDob);
		regProcLogger.info("Guardian DOB: " + parentOrGuardianDob);

		if (!checkApplicantAgeWithParentOrGuardian(applicantDob, parentOrGuardianDob, 20)) {

			logAndSetStatusError(registrationStatusDto,
					"Guardian (grandfather) is not at least 20 years older than the applicant for registrationId: "
							+ applicantFields.get("registrationId"),
					StatusUtil.CITIZENSHIP_VERIFICATION_AGE_DIFFERENCE_FAILED.getCode(),
					StatusUtil.CITIZENSHIP_VERIFICATION_AGE_DIFFERENCE_FAILED.getMessage(),
					RegistrationStatusCode.PROCESSING.toString(), description, applicantFields.get("registrationId"));
			isValidGuardian = false;
		}

		Map<String, String> guardian1Map = extractDemographicss(guardianRelationValue, guardianInfoJson);
		regProcLogger.info("Extracted demographics for {}: {}", guardianRelationValue, guardian1Map);

		Map<String, String> guardian2Map = extractApplicantDemographicss(applicantFields);
		regProcLogger.info("Extracted demographics for applicant: {}", guardian2Map);

		boolean isValidTribeAndClan = ValidateguardianTribeAndClan(guardian1Map, guardian2Map, registrationStatusDto,
				description, applicantFields);

		
		return isValidGuardian && isValidTribeAndClan;
	}

	private Map<String, String> extractDemographicss(String guardianRelationValue, JSONObject guardianInfoJson) {
		Map<String, String> guardian1Map = new HashMap<>();
		guardian1Map.put(MappingJsonConstants.PERSON, guardianRelationValue + " in NIRA System");
		ObjectMapper objectMapper = new ObjectMapper();

		extractAndPutValuee(guardian1Map, MappingJsonConstants.TRIBE, guardianInfoJson,
				MappingJsonConstants.GUARDIAN_TRIBE, objectMapper);
		extractAndPutValuee(guardian1Map, MappingJsonConstants.CLAN, guardianInfoJson,
				MappingJsonConstants.GUARDIAN_CLAN, objectMapper);

		return guardian1Map;
	}

	private void extractAndPutValuee(Map<String, String> map, String key, JSONObject jsonObject, String jsonKey,
			ObjectMapper objectMapper) {
		String jsonString = null;
		try {
			jsonString = jsonObject.get(jsonKey).toString();
		} catch (Exception e) {

		}
		if (jsonString != null && !jsonString.isEmpty()) {
			try {
				List<Map<String, String>> list = objectMapper.readValue(jsonString,
						new TypeReference<List<Map<String, String>>>() {
						});
				if (!list.isEmpty()) {
					map.put(key, list.get(0).get("value"));
				}
			} catch (Exception e) {

			}
		}
	}

	private Map<String, String> extractApplicantDemographicss(Map<String, String> applicantFields) {
		Map<String, String> guardian2Map = new HashMap<>();
		guardian2Map.put(MappingJsonConstants.PERSON, "Guardian in Form");
		ObjectMapper objectMapper = new ObjectMapper();

		extractAndPutValueee(guardian2Map, MappingJsonConstants.TRIBE_ON_FORM,
				applicantFields.get(MappingJsonConstants.GUARDIAN_TRIBE_FORM), objectMapper);
		extractAndPutValueee(guardian2Map, MappingJsonConstants.CLAN_ON_FORM,
				applicantFields.get(MappingJsonConstants.GUARDIAN_CLAN_FORM), objectMapper);

		return guardian2Map;
	}

	private void extractAndPutValueee(Map<String, String> map, String key, String jsonString,
			ObjectMapper objectMapper) {
		if (jsonString == null || jsonString.isEmpty()) {
			regProcLogger.error("JSON string is null or empty for key: " + key);
			return;
		}

		try {
			List<Map<String, String>> list = objectMapper.readValue(jsonString,
					new TypeReference<List<Map<String, String>>>() {
					});
			if (list.isEmpty()) {
				regProcLogger.error("JSON list is empty for key: " + key);
				return;
			}
			String value = list.get(0).get("value");
			if (value == null) {
				regProcLogger.error("Value is missing in the JSON list for key: " + key);
				return;
			}
			map.put(key, value);
		} catch (Exception e) {
			regProcLogger.error("Error parsing JSON string for key: " + key, e);
		}
	}

	private boolean validateSiblingRelationship(Map<String, String> applicantFields, JSONObject guardianInfoJson,
			InternalRegistrationStatusDto registrationStatusDto, LogDescription description)
			throws IdRepoAppException, ApisResourceAccessException {

		String guardianNin = applicantFields.get(MappingJsonConstants.GUARDIAN_NIN);
		if (guardianNin == null) {
			regProcLogger.warn("GUARDIAN_NIN is missing. Stopping further processing.");
			return false;
		} else {
			regProcLogger.info("GUARDIAN_NIN: " + guardianNin);
		}


		String guardianRelationToApplicantJson = applicantFields
				.get(MappingJsonConstants.GUARDIAN_RELATION_TO_APPLICANT);
		regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationToApplicantJson);

		ObjectMapper objectMapper = new ObjectMapper();

		String guardianRelationValue = null;
		try {
			List<Map<String, String>> guardianRelations = objectMapper.readValue(guardianRelationToApplicantJson,
					new TypeReference<List<Map<String, String>>>() {
					});
			guardianRelationValue = guardianRelations.get(0).get("value");
			regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationValue);
		} catch (Exception e) {
			regProcLogger.error("Error parsing GUARDIAN_RELATION_TO_APPLICANT JSON", e);
			return false;
		}


		boolean isValidGuardian = true;

		Map<String, String> guardian1Map = extractDemographicss(guardianRelationValue, guardianInfoJson);
		regProcLogger.info("Extracted demographics for {}: {}", guardianRelationValue, guardian1Map);

		Map<String, String> guardian2Map = extractApplicantDemographicss(applicantFields);
		regProcLogger.info("Extracted demographics for applicant: {}", guardian2Map);

        ValidateguardianTribeAndClan(guardian1Map, guardian2Map, registrationStatusDto, description,
				applicantFields);

		return isValidGuardian;
	}

	private boolean validateUncleAuntRelationship(Map<String, String> applicantFields, JSONObject guardianInfoJson,
			InternalRegistrationStatusDto registrationStatusDto, LogDescription description)
			throws IdRepoAppException, ApisResourceAccessException {

		String guardianNin = applicantFields.get(MappingJsonConstants.GUARDIAN_NIN);
		if (guardianNin == null) {
			regProcLogger.warn("GUARDIAN_NIN is missing. Stopping further processing.");
			return false;
		} else {
			regProcLogger.info("GUARDIAN_NIN: " + guardianNin);
		}


		String guardianRelationToApplicantJson = applicantFields
				.get(MappingJsonConstants.GUARDIAN_RELATION_TO_APPLICANT);
		regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationToApplicantJson);

		ObjectMapper objectMapper = new ObjectMapper();

		String guardianRelationValue = null;
		try {
			List<Map<String, String>> guardianRelations = objectMapper.readValue(guardianRelationToApplicantJson,
					new TypeReference<List<Map<String, String>>>() {
					});
			guardianRelationValue = guardianRelations.get(0).get("value");
			regProcLogger.info("GUARDIAN_RELATION_TO_APPLICANT: " + guardianRelationValue);
		} catch (Exception e) {
			regProcLogger.error("Error parsing GUARDIAN_RELATION_TO_APPLICANT JSON", e);
			return false;
		}


		boolean isValidGuardian = true;

		Map<String, String> guardian1Map = extractDemographicss(guardianRelationValue, guardianInfoJson);
		regProcLogger.info("Extracted demographics for {}: {}", guardianRelationValue, guardian1Map);

		Map<String, String> guardian2Map = extractApplicantDemographicss(applicantFields);
		regProcLogger.info("Extracted demographics for applicant: {}", guardian2Map);

		ValidateguardianTribeAndClan(guardian1Map, guardian2Map, registrationStatusDto, description,
				applicantFields);

		return isValidGuardian;
	}
	
	
	private boolean ValidateguardianTribeAndClan(Map<String, String> guardian1, Map<String, String> guardian2,
			InternalRegistrationStatusDto registrationStatusDto, LogDescription description,
			Map<String, String> applicantFields) {
		Boolean isValid = false;
		if (guardian1.get(MappingJsonConstants.TRIBE).equalsIgnoreCase(guardian2.get(MappingJsonConstants.TRIBE))) {

			if (guardian1.get(MappingJsonConstants.CLAN).equalsIgnoreCase(guardian2.get(MappingJsonConstants.CLAN))) {

				{
					isValid = true;

				}
			} else {

				logAndSetStatusError(registrationStatusDto,
						"Mismatch in " + guardian1.get(MappingJsonConstants.PERSON) + ", "
								+ guardian2.get(MappingJsonConstants.PERSON) + "'s " + MappingJsonConstants.CLAN
								+ " information.",
						StatusUtil.CITIZENSHIP_VERIFICATION_CLAN_MISMATCH.getCode(),
						StatusUtil.CITIZENSHIP_VERIFICATION_CLAN_MISMATCH.getMessage(),
						RegistrationStatusCode.PROCESSING.toString(), description,
						applicantFields.get("registrationId"));
			}
		} else {

			logAndSetStatusError(registrationStatusDto,
					"Mismatch in " + guardian1.get(MappingJsonConstants.PERSON) + ", "
							+ guardian2.get(MappingJsonConstants.PERSON) + "'s " + MappingJsonConstants.TRIBE
							+ " information.",
					StatusUtil.CITIZENSHIP_VERIFICATION_TRIBE_MISMATCH.getCode(),
					StatusUtil.CITIZENSHIP_VERIFICATION_TRIBE_MISMATCH.getMessage(),
					RegistrationStatusCode.PROCESSING.toString(), description, applicantFields.get("registrationId"));
		}

		return isValid;
	}

}
