package io.mosip.registration.processor.packet.storage.entity;

import java.io.Serializable;
import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "transaction_type", schema = "regprc")
public class TransactionTypeEntity extends BasePacketEntity<TransactionTypePKEntity> implements Serializable {
	private static final long serialVersionUID = 1L;

	@Column(name = "descr")
	private String description;

	/** The is active. */
	@Column(name = "is_active")
	private Boolean isActive;

	/** The is deleted. */
	@Column(name = "is_deleted")
	private Boolean isDeleted;

	@Column(name = "cr_by")
	private String crBy;

	@Column(name = "cr_dtimes", updatable = false)
	private LocalDateTime crDtimes;

	@Column(name = "del_dtimes")
	private LocalDateTime delDtimes;

	@Column(name = "upd_by")
	private String updBy;

	@Column(name = "upd_dtimes")
	private LocalDateTime updDtimes;

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Boolean getIsActive() {
		return isActive;
	}

	public void setIsActive(Boolean isActive) {
		this.isActive = isActive;
	}

	public Boolean getIsDeleted() {
		return isDeleted;
	}

	public void setIsDeleted(Boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

	public String getCrBy() {
		return crBy;
	}

	public void setCrBy(String crBy) {
		this.crBy = crBy;
	}

	public LocalDateTime getCrDtimes() {
		return crDtimes;
	}

	public void setCrDtimes(LocalDateTime crDtimes) {
		this.crDtimes = crDtimes;
	}

	public LocalDateTime getDelDtimes() {
		return delDtimes;
	}

	public void setDelDtimes(LocalDateTime delDtimes) {
		this.delDtimes = delDtimes;
	}

	public String getUpdBy() {
		return updBy;
	}

	public void setUpdBy(String updBy) {
		this.updBy = updBy;
	}

	public LocalDateTime getUpdDtimes() {
		return updDtimes;
	}

	public void setUpdDtimes(LocalDateTime updDtimes) {
		this.updDtimes = updDtimes;
	}

}
