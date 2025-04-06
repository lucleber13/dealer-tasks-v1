package com.cbcode.dealertasksV1.Cars.model.DTOs;

import com.cbcode.dealertasksV1.Cars.model.Enums.CarStatus;
import com.cbcode.dealertasksV1.Users.model.DTOs.UserDto;

public record DisplayCarsDto(
        Long id,
        String regNumber,
        String chassisNumber,
        String model,
        String color,
        Integer keyNumber,
        CarStatus carStockSold,
        UserDto userDto // TODO: review the user from Task
) {
}
