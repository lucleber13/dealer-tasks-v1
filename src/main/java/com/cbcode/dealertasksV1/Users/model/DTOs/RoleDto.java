package com.cbcode.dealertasksV1.Users.model.DTOs;

import com.cbcode.dealertasksV1.Users.model.Enums.EnumRole;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

import java.util.Objects;

public class RoleDto {

    private Integer id;
    @Enumerated(EnumType.STRING)
    private EnumRole name;

    public RoleDto() {
    }

    public RoleDto(EnumRole name) {
        this.name = name;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public EnumRole getName() {
        return name;
    }

    public void setName(EnumRole name) {
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof RoleDto roleDto)) return false;
        return Objects.equals(id, roleDto.id)
                && name == roleDto.name;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name);
    }
}
