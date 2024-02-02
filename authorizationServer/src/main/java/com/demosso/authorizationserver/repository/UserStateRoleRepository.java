package com.demosso.authorizationserver.repository;

import com.demosso.authorizationserver.domain.UserStateRole;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserStateRoleRepository extends CrudRepository<UserStateRole, String> {
	Optional<UserStateRole> findRoleByUserState(String state);

}