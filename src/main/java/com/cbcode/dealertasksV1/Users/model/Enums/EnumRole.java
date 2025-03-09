package com.cbcode.dealertasksV1.Users.model.Enums;

public enum EnumRole {
    ROLE_ADMIN("Admin"),
    ROLE_SALES("Sales"),
    ROLE_WORKSHOP("Workshop"),
    ROLE_VALETER("Valeter");

    private final String role;

    EnumRole(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    /**
     * This method returns the EnumRole object that corresponds to the role passed as a parameter.
     * @param role The role to be converted to EnumRole.
     * @return The EnumRole object that corresponds to the role passed as a parameter.
     */
    public static EnumRole getEnumRole(String role) {
        for (EnumRole enumRole : EnumRole.values()) {
            if (enumRole.getRole().equals(role)) {
                return enumRole;
            }
        }
        return null;
    }
}
