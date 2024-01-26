package com.demosso.authorizationserver.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity(name = "User")
@Table(name = "app_user")
public class User implements Serializable {

	private static final long OTP_VALID_DURATION = 5 * 60 * 1000;   // 5 minutes

	@Id
	@UuidGenerator(style = UuidGenerator.Style.TIME)
	@Column(name = "id", updatable = false, nullable = false)
	private UUID id;

	//TODO reference to clients table
	private String clientId;

	@JsonIgnore
	@ManyToMany(cascade = CascadeType.MERGE, fetch = FetchType.EAGER)
	@JoinTable(name = "user_role",
		joinColumns = @JoinColumn(name = "user_id"),
		inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new HashSet<>();

	@Column(nullable = false, unique = true)
	private String username;

	private String password;

	private String firstName;

	private String middleName;

	private String lastName;

	private String locale;

	private String avatarUrl;

	private boolean active;

	@CreationTimestamp
	protected LocalDateTime createdAt;

	private String otp;

	private LocalDateTime otpRequestedAt;


	//TODO move to another class
	public boolean isOTPRequired() {
		if (this.getOtp() == null) {
			return false;
		}

		long currentTimeInMillis = System.currentTimeMillis();
		//TODO fix hardcoded zone
		long otpRequestedTimeInMillis = this.otpRequestedAt.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();

		if (otpRequestedTimeInMillis + OTP_VALID_DURATION < currentTimeInMillis) {
			// OTP expires
			return false;
		}

		return true;
	}
}
