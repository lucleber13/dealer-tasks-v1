package com.cbcode.dealertasksV1.Users.repository;

import com.cbcode.dealertasksV1.Users.model.Enums.EnumRole;
import com.cbcode.dealertasksV1.Users.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

    @Query("SELECT r FROM Role r WHERE r.name = :name")
    Optional<Role> findByName(@Param("name") EnumRole name);

    List<String> findUserRolesById(Long id);
}
